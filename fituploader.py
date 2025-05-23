#!/usr/bin/env python3
"""
FitUploader
Usage: "python3 fituploader.py"
Description:
    - Interface graphique pour se connecter à Garmin Connect avec persistance de session.
    - Détection et traitement automatiques des fichiers FIT de MyWhoosh.
    - Upload multi-fichiers avec suivi de progression.
    - Sauvegarde des fichiers traités avec préfixe 'MW_' dans un dossier configurable.
    - Nettoyage automatique des fichiers uploadés avec sauvegarde optionnelle.
    - Sauvegarde persistante de l'email et des chemins de configuration dans le dossier home.
    - Interface compacte et moderne avec notifications, indicateurs de statut et contenu défilant.
    - Upload multi-threadé pour éviter le gel de l'interface.
    - Support du défilement par molette de souris pour toute l'interface.
    - Journal d'activité horodaté pour suivre les opérations.
"""

import os
import json
import subprocess
import sys
import logging
import re
import threading
import time
from typing import List, Tuple, Optional, Dict
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import importlib.util
import queue

# --- Configuration globale et journalisation ---
SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / "FitUploader.log"
CONFIG_FILE = Path.home() / ".fituploader_config.json"
TOKENS_PATH = SCRIPT_DIR / ".garth"
INSTALLED_PACKAGES_FILE = SCRIPT_DIR / "installed_packages.json"

# Constantes
MW_PREFIX = "MW_"
MYWHOOSH_PREFIX_WINDOWS = "TheWhooshGame"

# Couleurs pour une interface moderne
COLORS = {
    'primary': '#2563eb',
    'success': '#10b981',
    'warning': '#f59e0b',
    'error': '#ef4444',
    'background': '#f8fafc',
    'surface': '#ffffff',
    'text': '#1e293b',
    'text_secondary': '#64748b'
}

# Configuration du journal
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# --- Gestion de configuration ---
def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            with CONFIG_FILE.open("r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Erreur de lecture de config: {e}")
    return {}

def save_config(config: dict) -> None:
    try:
        with CONFIG_FILE.open("w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.error(f"Erreur d'écriture de config: {e}")

config = load_config()

# --- Gestion de l'installation des packages requis ---
def load_installed_packages() -> set:
    if INSTALLED_PACKAGES_FILE.exists():
        with INSTALLED_PACKAGES_FILE.open("r") as f:
            return set(json.load(f))
    return set()

def save_installed_packages(installed_packages: set) -> None:
    with INSTALLED_PACKAGES_FILE.open("w") as f:
        json.dump(list(installed_packages), f)

def get_pip_command() -> Optional[list]:
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return [sys.executable, "-m", "pip"]
    except subprocess.CalledProcessError:
        return None

def install_package(package: str) -> None:
    pip_command = get_pip_command()
    if pip_command:
        try:
            logger.info(f"Installation du package manquant: {package}.")
            subprocess.check_call(pip_command + ["install", package])
        except subprocess.CalledProcessError as e:
            logger.error(f"Erreur lors de l'installation de {package}: {e}.")
    else:
        logger.error("pip n'est pas disponible.")

def ensure_packages() -> None:
    required_packages = ["garth", "fit_tool"]
    installed_packages = load_installed_packages()
    for package in required_packages:
        if package in installed_packages:
            logger.info(f"Le package {package} est déjà installé.")
            continue
        if not importlib.util.find_spec(package):
            logger.info(f"Le package {package} n'a pas été trouvé. Installation en cours...")
            install_package(package)
        try:
            __import__(package)
            logger.info(f"Importation de {package} réussie.")
            installed_packages.add(package)
        except ModuleNotFoundError:
            logger.error(f"Échec de l'importation de {package} après installation.")
    save_installed_packages(installed_packages)

ensure_packages()

# --- Import des modules tiers ---
try:
    import garth
    from garth.exc import GarthException, GarthHTTPError
    from fit_tool.fit_file import FitFile
    from fit_tool.fit_file_builder import FitFileBuilder
    from fit_tool.profile.messages.file_creator_message import FileCreatorMessage
    from fit_tool.profile.messages.record_message import RecordMessage, RecordTemperatureField
    from fit_tool.profile.messages.session_message import SessionMessage
    from fit_tool.profile.messages.lap_message import LapMessage
except ImportError as e:
    logger.error(f"Erreur d'importation des modules tiers: {e}")
    sys.exit(1)

# --- Fonctions utilitaires pour les fichiers FIT ---
def get_mywhoosh_directory() -> Path:
    """Retourne le chemin du répertoire MyWhoosh selon l'OS."""
    if os.name == "posix":  # macOS et Linux
        target = (Path.home() / "Library" / "Containers" / "com.whoosh.whooshgame" /
                  "Data" / "Library" / "Application Support" / "Epic" / "MyWhoosh" /
                  "Content" / "Data")
        if target.is_dir():
            return target
        logger.error(f"Le répertoire MyWhoosh {target} est introuvable.")
        return Path()
    elif os.name == "nt":  # Windows
        try:
            base = Path.home() / "AppData" / "Local" / "Packages"
            for directory in base.iterdir():
                if directory.is_dir() and directory.name.startswith(MYWHOOSH_PREFIX_WINDOWS):
                    target = directory / "LocalCache" / "Local" / "MyWhoosh" / "Content" / "Data"
                    if target.is_dir():
                        return target
            logger.error("Répertoire MyWhoosh introuvable.")
            return Path()
        except Exception as e:
            logger.error(str(e))
            return Path()
    else:
        logger.error("OS non supporté.")
        return Path()

def get_backup_path() -> Optional[Path]:
    """Retourne le chemin de sauvegarde pour les fichiers traités."""
    path = config.get("backup_path", "")
    if path and Path(path).is_dir():
        return Path(path)
    return None

def calculate_avg(values: List[int]) -> int:
    return int(sum(values) / len(values)) if values else 0

def append_value(values: List[int], message: object, field_name: str) -> None:
    value = getattr(message, field_name, None)
    values.append(value if value is not None else 0)

def reset_values() -> Tuple[List[int], List[int], List[int]]:
    return [], [], []

def cleanup_fit_file(fit_file_path: Path, new_file_path: Path) -> bool:
    """Traite le fichier FIT : supprime la température, calcule les moyennes, et sauvegarde dans un nouveau fichier."""
    try:
        builder = FitFileBuilder()
        fit_file = FitFile.from_file(str(fit_file_path))
        cadence_values, power_values, heart_rate_values = reset_values()
        
        for record in fit_file.records:
            message = record.message
            if isinstance(message, LapMessage):
                continue
            if isinstance(message, RecordMessage):
                message.remove_field(RecordTemperatureField.ID)
                append_value(cadence_values, message, "cadence")
                append_value(power_values, message, "power")
                append_value(heart_rate_values, message, "heart_rate")
            if isinstance(message, SessionMessage):
                if not message.avg_cadence:
                    message.avg_cadence = calculate_avg(cadence_values)
                if not message.avg_power:
                    message.avg_power = calculate_avg(power_values)
                if not message.avg_heart_rate:
                    message.avg_heart_rate = calculate_avg(heart_rate_values)
                cadence_values, power_values, heart_rate_values = reset_values()
            builder.add(message)
        
        builder.build().to_file(str(new_file_path))
        logger.info(f"Fichier nettoyé sauvegardé sous {new_file_path.name}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors du nettoyage du fichier {fit_file_path.name}: {e}")
        return False

def get_fit_files(source_dir: Path) -> List[Path]:
    """Retourne la liste des fichiers FIT dans le répertoire source."""
    if not source_dir or not source_dir.is_dir():
        return []
    return sorted(list(source_dir.glob("MyNewActivity-*.fit")), 
                  key=lambda f: f.stat().st_mtime, reverse=True)

def get_processed_files_info() -> Dict[str, datetime]:
    """Retourne les informations sur les fichiers déjà traités."""
    processed_info = config.get("processed_files", {})
    for key, timestamp in processed_info.items():
        if isinstance(timestamp, (int, float)):
            processed_info[key] = datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, str):
            try:
                processed_info[key] = datetime.fromisoformat(timestamp)
            except:
                processed_info[key] = datetime.now()
    return processed_info

def save_processed_file_info(file_path: Path) -> None:
    """Sauvegarde l'information qu'un fichier a été traité."""
    processed_info = config.get("processed_files", {})
    file_key = f"{file_path.name}_{file_path.stat().st_size}"
    processed_info[file_key] = datetime.now().isoformat()
    config["processed_files"] = processed_info
    save_config(config)

def is_file_already_processed(file_path: Path) -> bool:
    """Vérifie si un fichier a déjà été traité."""
    processed_info = get_processed_files_info()
    file_key = f"{file_path.name}_{file_path.stat().st_size}"
    return file_key in processed_info

def generate_new_filename(fit_file: Path) -> str:
    """Génère un nouveau nom de fichier avec préfixe MW_ et horodatage."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    match = re.search(r'MyNewActivity-(\d+)\.fit', fit_file.name)
    activity_num = f"_{match.group(1)}" if match else ""
    return f"{MW_PREFIX}{timestamp}{activity_num}.fit"

def cleanup_old_backup_files(backup_dir: Path, max_files: int = 50) -> None:
    """Nettoie les anciens fichiers de sauvegarde pour éviter l'accumulation."""
    if not backup_dir.exists():
        return
    fit_files = list(backup_dir.glob("*.fit"))
    if len(fit_files) > max_files:
        fit_files.sort(key=lambda f: f.stat().st_mtime)
        files_to_remove = fit_files[:-max_files]
        for file_path in files_to_remove:
            try:
                file_path.unlink()
                logger.info(f"Ancien fichier de sauvegarde supprimé: {file_path.name}")
            except Exception as e:
                logger.error(f"Erreur lors de la suppression de {file_path.name}: {e}")

def get_available_sources() -> Dict[str, Path]:
    """Retourne un dictionnaire des sources disponibles avec leur chemin."""
    sources = {}
    myw_dir = get_mywhoosh_directory()
    if myw_dir and myw_dir.is_dir():
        sources["MyWhoosh"] = myw_dir
    return sources

def get_new_fit_files(sources: Dict[str, Path]) -> List[Tuple[Path, str]]:
    """Retourne les nouveaux fichiers FIT non traités avec leur source."""
    new_files = []
    for source_name, source_dir in sources.items():
        if not source_dir or not source_dir.is_dir():
            continue
        fit_files = get_fit_files(source_dir)
        for fit_file in fit_files:
            if not is_file_already_processed(fit_file):
                new_files.append((fit_file, source_name))
    return new_files

# --- Fonctions d'authentification ---
def authenticate_to_garmin_gui(email: str, password: str) -> bool:
    """Authentifie l'utilisateur sur Garmin Connect."""
    logger.info("Tentative d'authentification sur Garmin Connect...")
    try:
        garth.login(email, password)
        garth.save(TOKENS_PATH)
        config["last_auth"] = datetime.now().isoformat()
        save_config(config)
        logger.info(f"Authentification réussie pour {email}.")
        return True
    except GarthHTTPError as e:
        logger.error(f"Erreur d'authentification HTTP: {e}")
        return False
    except Exception as e:
        logger.error(f"Erreur d'authentification: {e}")
        return False

def try_token_auth() -> bool:
    """Tente d'authentifier avec un token existant."""
    if not TOKENS_PATH.exists():
        return False
    try:
        garth.resume(TOKENS_PATH)
        garth.client.username
        logger.info("Authentification par token réussie.")
        return True
    except Exception as e:
        logger.info(f"Token expiré ou invalide: {e}")
        try:
            TOKENS_PATH.unlink()
        except:
            pass
        return False

def is_session_valid() -> bool:
    """Vérifie si la session Garmin est encore valide."""
    try:
        garth.client.username
        return True
    except:
        return False

def refresh_garmin_session() -> bool:
    """Rafraîchit la session Garmin si nécessaire."""
    if is_session_valid():
        return True
    return try_token_auth()

def upload_fit_files_to_garmin(files: List[Path]) -> Dict[Path, bool]:
    """Upload les fichiers FIT vers Garmin Connect avec gestion des erreurs."""
    results = {}
    for file_path in files:
        try:
            if not file_path.exists():
                logger.error(f"Fichier inexistant: {file_path}")
                results[file_path] = False
                continue
            if not refresh_garmin_session():
                logger.error("Session Garmin expirée et impossible de la renouveler")
                results[file_path] = False
                continue
            logger.info(f"Envoi du fichier {file_path.name} vers Garmin Connect...")
            with open(file_path, "rb") as f:
                response = garth.client.upload(f)
                logger.debug(f"Réponse Garmin: {response}")
            results[file_path] = True
            logger.info(f"Upload réussi pour {file_path.name}")
            save_processed_file_info(file_path)
            time.sleep(1)
        except GarthHTTPError as e:
            if "409 Client Error" in str(e):
                logger.info(f"Le fichier {file_path.name} est déjà présent sur Garmin Connect.")
                results[file_path] = True
                save_processed_file_info(file_path)
            else:
                logger.error(f"Erreur HTTP lors de l'upload de {file_path.name}: {e}")
                results[file_path] = False
        except Exception as e:
            logger.error(f"Erreur inattendue lors de l'upload de {file_path.name}: {e}")
            results[file_path] = False
    return results

# --- Gestionnaire de log pour l'interface ---
class TextHandler(logging.Handler):
    def __init__(self, widget: tk.Text):
        super().__init__()
        self.widget = widget
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.widget.configure(state='normal')
            tag = "info"
            if record.levelno >= logging.ERROR:
                tag = "error"
            elif record.levelno >= logging.WARNING:
                tag = "warning"
            elif record.levelno >= logging.INFO:
                tag = "info"
            self.widget.insert(tk.END, msg + "\n", tag)
            self.widget.configure(state='disabled')
            self.widget.yview(tk.END)
        self.widget.after(0, append)

# --- Fonction pour les info-bulles ---
def create_tooltip(widget, text):
    """Crée une info-bulle pour un widget."""
    tooltip = None
    
    def enter(event):
        nonlocal tooltip
        x, y, _, _ = widget.bbox("insert")
        x += widget.winfo_rootx() + 25
        y += widget.winfo_rooty() + 25
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1,
                        font=("Segoe UI", 8), padx=5, pady=2)
        label.pack()
    
    def leave(event):
        nonlocal tooltip
        if tooltip:
            tooltip.destroy()
            tooltip = None
    
    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)

# --- Application Tkinter ---
class FitUploaderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FitUploader")
        # Taille initiale de la fenêtre. Modifiez ici pour ajuster (par ex. "800x600" ou "700x500")
        self.geometry("770x670")
        self.minsize(770, 570)
        self.configure(bg=COLORS['background'])

         # Configurer l'icône de la fenêtre
        if os.name == "nt":  # Windows
            icon_path = SCRIPT_DIR / "FitUploader.ico"
            if icon_path.exists():
                self.iconbitmap(str(icon_path))
        elif os.name == "posix":  # macOS/Linux
            icon_path = SCRIPT_DIR / "FitUploader.png"
            if icon_path.exists():
                icon_img = tk.PhotoImage(file=str(icon_path))
                self.iconphoto(True, icon_img)
        
        # Variables d'état
        self.is_connected = False
        self.is_processing = False
        self.upload_queue = queue.Queue()
        self.fit_files = []
        self.selected_files = set()
        
        # Configuration initiale
        self.setup_style()
        self.create_widgets()
        self.add_logging_handler()
        
        # Charger les paramètres sauvegardés
        if config.get("username"):
            self.email.set(config["username"])
        self.sauvegarde_path.set(config.get("backup_path", ""))
        
        # Tenter une authentification automatique
        self.auto_authenticate()
        
        # Scanner les fichiers au démarrage
        self.scan_files()
        
        # Démarrer la vérification de la queue
        self.check_queue()

    def setup_style(self):
        """Configure le style moderne de l'interface."""
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        base_font = ("Segoe UI", 9)
        heading_font = ("Segoe UI", 10, "bold")
        self.style.configure("Title.TLabel", font=heading_font, foreground=COLORS['text'])
        self.style.configure("Subtitle.TLabel", font=base_font, foreground=COLORS['text_secondary'])
        self.style.configure("Success.TLabel", font=base_font, foreground=COLORS['success'])
        self.style.configure("Error.TLabel", font=base_font, foreground=COLORS['error'])
        self.style.configure("Warning.TLabel", font=base_font, foreground=COLORS['warning'])
        self.style.configure("Primary.TButton", font=base_font, 
                           foreground="white", background=COLORS['primary'], padding=5)
        self.style.map("Primary.TButton", background=[("active", "#1d4ed8")])
        self.style.configure("Success.TButton", font=base_font,
                           foreground="#000000", background=COLORS['success'], padding=5)
        self.style.map("Success.TButton", background=[("active", "#059669")])
        self.style.configure("Danger.TButton", font=base_font,
                           foreground="white", background=COLORS['error'], padding=5)
        self.style.map("Danger.TButton", background=[("active", "#dc2626")])

    def create_widgets(self):
        """Crée l'interface utilisateur compacte."""
        # Canvas principal avec barre de défilement
        main_canvas = tk.Canvas(self, bg=COLORS['background'])
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=main_canvas.yview)
        scrollable_frame = ttk.Frame(main_canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        main_canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Support de la molette de souris
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # === SECTION AUTHENTIFICATION ===
        auth_frame = ttk.LabelFrame(scrollable_frame, text="Authentification Garmin Connect", padding=6)
        auth_frame.pack(fill="x", pady=(0, 5))
        auth_frame.columnconfigure(1, weight=1)
        
        # Email
        ttk.Label(auth_frame, text="Email:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.email = tk.StringVar()
        email_entry = ttk.Entry(auth_frame, textvariable=self.email, width=40)
        email_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        
        # Mot de passe
        ttk.Label(auth_frame, text="Mot de passe:").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=(2, 0))
        self.password = tk.StringVar()
        password_entry = ttk.Entry(auth_frame, textvariable=self.password, show="*", width=40)
        password_entry.grid(row=1, column=1, sticky="ew", padx=(0, 5), pady=(2, 0))
        
        # Options
        self.remember_email = tk.BooleanVar(value=True)
        ttk.Checkbutton(auth_frame, text="Se souvenir de l'email", 
                       variable=self.remember_email).grid(row=2, column=0, sticky="w", pady=(2, 0))
        
        # Bouton de connexion/déconnexion
        self.login_button = ttk.Button(auth_frame, text="Se connecter", 
                                     command=self.login, style="Primary.TButton")
        self.login_button.grid(row=2, column=1, sticky="w", pady=(2, 0))
        
        # Statut
        self.auth_status = ttk.Label(auth_frame, text="✗ Non connecté", style="Error.TLabel")
        self.auth_status.grid(row=3, column=0, columnspan=2, pady=(2, 0))
        
        # === SECTION CONFIGURATION ===
        config_frame = ttk.LabelFrame(scrollable_frame, text="Configuration", padding=6)
        config_frame.pack(fill="x", pady=(0, 5))
        config_frame.columnconfigure(1, weight=1)
        
        # Sauvegarde
        ttk.Label(config_frame, text="Dossier de sauvegarde :").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.sauvegarde_path = tk.StringVar()
        sauvegarde_entry = ttk.Entry(config_frame, textvariable=self.sauvegarde_path, width=50)
        sauvegarde_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        change_button = ttk.Button(config_frame, text="Changer", 
                                 command=self.browse_folder)
        change_button.grid(row=0, column=2, sticky="w")
        create_tooltip(change_button, "Sélectionner le dossier où les fichiers FIT traités seront archivés avant suppression")
        
        # Sources détectées
        ttk.Label(config_frame, text="Source MyWhoosh:", style="Subtitle.TLabel").grid(row=1, column=0, columnspan=3, sticky="w", pady=(5, 2))
        self.sources_label = ttk.Label(config_frame, text="Chargement...", font=('TkDefaultFont', 8))
        self.sources_label.grid(row=2, column=0, columnspan=3, sticky="w")
        
        # === SECTION FICHIERS FIT ===
        files_frame = ttk.LabelFrame(scrollable_frame, text="Fichiers FIT disponibles", padding=6)
        files_frame.pack(fill="both", expand=True, pady=(0, 5))
        
        # En-tête
        header_frame = ttk.Frame(files_frame)
        header_frame.pack(fill="x", pady=(0, 5))
        self.files_count_label = ttk.Label(header_frame, text="Aucun fichier trouvé")
        self.files_count_label.pack(side="left")
        ttk.Button(header_frame, text="🔄 Actualiser", 
                  command=self.scan_files).pack(side="left", padx=(5, 0))
        
        # Treeview
        columns = ('name', 'size', 'date')
        self.files_tree = ttk.Treeview(files_frame, columns=columns, show='tree headings', height=5)
        self.files_tree.heading('#0', text='')
        self.files_tree.heading('name', text='Nom du fichier')
        self.files_tree.heading('size', text='Taille')
        self.files_tree.heading('date', text='Date')
        self.files_tree.column('#0', width=30, stretch=False)
        self.files_tree.column('name', width=280)
        self.files_tree.column('size', width=65)
        self.files_tree.column('date', width=100)
        
        tree_scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        tree_frame = ttk.Frame(files_frame)
        tree_frame.pack(fill="both", expand=True)
        self.files_tree.pack(side="left", fill="both", expand=True)
        tree_scrollbar.pack(side="right", fill="y")
        
        self.files_tree.bind('<Button-1>', self.on_tree_click)
        self.files_tree.bind('<space>', self.toggle_selection)
        
        # Sélection
        selection_frame = ttk.Frame(files_frame)
        selection_frame.pack(fill="x", pady=(5, 0))
        
        # Menu déroulant pour sélection
        self.selection_var = tk.StringVar(value="Actions...")
        selection_menu = ttk.OptionMenu(selection_frame, self.selection_var, "Actions...", 
                                      "Tout sélectionner", "Tout désélectionner", 
                                      command=self.handle_selection_action)
        selection_menu.pack(side="top", anchor="w")
        
        self.auto_select_new = tk.BooleanVar(value=True)
        ttk.Checkbutton(selection_frame, text="Auto-sélection nouveaux fichiers",
                       variable=self.auto_select_new).pack(side="top", anchor="w", pady=(2, 0))
        
        # === SECTION UPLOAD ===
        upload_frame = ttk.LabelFrame(scrollable_frame, text="Upload", padding=6)
        upload_frame.pack(fill="x", pady=(0, 5))
        
        buttons_frame = ttk.Frame(upload_frame)
        buttons_frame.pack(fill="x")
        self.upload_button = ttk.Button(buttons_frame, text="📤 Upload vers Garmin Connect", 
                                      command=self.upload_to_garmin, style="Success.TButton", width=25)
        self.upload_button.pack(side="left")
        ttk.Button(buttons_frame, text="🧹 Nettoyer fichiers uploadés", 
                  command=self.cleanup_uploaded).pack(side="left", padx=(5, 0))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(upload_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.pack(fill="x", pady=(5, 2))
        
        self.status_label = ttk.Label(upload_frame, text="Prêt à uploader")
        self.status_label.pack()
        
        # === SECTION LOG ===
        log_frame = ttk.LabelFrame(scrollable_frame, text="Journal", padding=6)
        log_frame.pack(fill="both", expand=True)
        
        self.log_text = tk.Text(log_frame, height=4, wrap=tk.WORD, state="disabled", 
                               font=("Consolas", 8), bg=COLORS['surface'])
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        self.log_text.tag_config("error", foreground=COLORS['error'])
        self.log_text.tag_config("warning", foreground=COLORS['warning'])
        self.log_text.tag_config("info", foreground=COLORS['primary'])
        self.log_text.tag_config("success", foreground=COLORS['success'])
        
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")
        
        ttk.Button(log_frame, text="Vider", command=self.clear_logs).pack(anchor="nw", pady=(2, 0))
        
        # Initialiser l'affichage
        self.update_ui_state()
        self.update_config_display()

    def add_logging_handler(self):
        """Ajoute un gestionnaire de log pour l'interface."""
        text_handler = TextHandler(self.log_text)
        logger.addHandler(text_handler)

    def update_ui_state(self):
        """Met à jour l'état de l'interface utilisateur."""
        state = "normal" if self.is_connected and not self.is_processing else "disabled"
        self.upload_button.configure(state=state)
        self.auth_status.configure(
            text="✓ Connecté à Garmin Connect" if self.is_connected else "✗ Non connecté",
            style="Success.TLabel" if self.is_connected else "Error.TLabel"
        )
        self.login_button.configure(
            text="Déconnecter" if self.is_connected else "Se connecter",
            style="Danger.TButton" if self.is_connected else "Primary.TButton"
        )

    def auto_authenticate(self):
        """Tente une authentification automatique."""
        if try_token_auth():
            self.is_connected = True
            self.update_ui_state()
            self.log("Connexion automatique réussie")
        else:
            self.log("Aucune session sauvegardée trouvée")

    def login(self):
        """Gère la connexion/déconnexion."""
        if self.is_connected:
            self.is_connected = False
            try:
                if TOKENS_PATH.exists():
                    TOKENS_PATH.unlink()
            except:
                pass
            self.update_ui_state()
            self.log("Déconnecté de Garmin Connect")
        else:
            email = self.email.get().strip()
            password = self.password.get().strip()
            if not email or not password:
                self.log("Veuillez saisir votre email et mot de passe", "warning")
                return
            self.login_button.configure(state="disabled", text="Connexion...")
            
            def authenticate():
                success = authenticate_to_garmin_gui(email, password)
                def update_ui():
                    self.login_button.configure(state="normal")
                    if success:
                        self.is_connected = True
                        if self.remember_email.get():
                            config["username"] = email
                            save_config(config)
                        self.password.set("")
                        self.log(f"Connexion réussie pour {email}", "success")
                    else:
                        self.log("Échec de la connexion. Vérifiez vos identifiants.", "error")
                    self.update_ui_state()
                self.after(0, update_ui)
            
            threading.Thread(target=authenticate, daemon=True).start()

    def browse_folder(self):
        """Ouvre un dialogue pour sélectionner un dossier."""
        folder = filedialog.askdirectory(initialdir=self.sauvegarde_path.get() or str(Path.home()))
        if folder:
            self.sauvegarde_path.set(folder)
            config["backup_path"] = folder
            save_config(config)
            self.update_config_display()
            self.log(f"Dossier de sauvegarde configuré: {Path(folder).name}", "success")

    def update_config_display(self):
        """Met à jour l'affichage de la configuration."""
        backup_path = get_backup_path()
        self.sauvegarde_path.set(str(backup_path) if backup_path else "")
        sources = get_available_sources()
        sources_text = "\n".join(f"✓ {name}: {path}" for name, path in sources.items()) or "Aucune source FIT détectée."
        self.sources_label.configure(text=sources_text)

    def scan_files(self):
        """Scan les dossiers pour trouver les fichiers FIT."""
        self.fit_files = []
        sources = get_available_sources()
        new_files = get_new_fit_files(sources)
        
        for file_path, source in new_files:
            stat = file_path.stat()
            self.fit_files.append({
                'name': file_path.name,
                'path': file_path,
                'size': self.format_size(stat.st_size),
                'date': datetime.fromtimestamp(stat.st_mtime).strftime('%d/%m/%Y %H:%M'),
                'source': source,
                'processed': is_file_already_processed(file_path)
            })
        
        self.update_files_display()

    def update_files_display(self):
        """Met à jour l'affichage des fichiers dans le treeview."""
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
        self.selected_files.clear()
        
        sources = {}
        for file_info in self.fit_files:
            source = file_info['source']
            if source not in sources:
                sources[source] = []
            sources[source].append(file_info)
        
        for source, files in sources.items():
            source_id = self.files_tree.insert('', 'end', text='', values=(f"{source} ({len(files)} fichiers)", '', ''))
            for file_info in files:
                file_id = self.files_tree.insert(source_id, 'end', 
                                               text='☑' if not file_info['processed'] and self.auto_select_new.get() else '✓' if file_info['processed'] else '☐',
                                               values=(file_info['name'], file_info['size'], file_info['date']))
                if not file_info['processed'] and self.auto_select_new.get():
                    self.selected_files.add(file_id)
        
        for item in self.files_tree.get_children():
            self.files_tree.item(item, open=True)
        
        self.files_count_label.configure(text=f"{len(self.fit_files)} fichier(s) trouvé(s)")
        self.log(f"{len(self.fit_files)} fichier(s) FIT détecté(s)")

    def on_tree_click(self, event):
        """Gère les clics sur le treeview."""
        item = self.files_tree.identify_row(event.y)
        if not item or not self.files_tree.parent(item):
            return
        file_info = next((f for f in self.fit_files if f['name'] == self.files_tree.item(item)['values'][0]), None)
        if file_info and not file_info['processed']:
            self.toggle_file_selection(item)

    def toggle_file_selection(self, item):
        """Inverse la sélection d'un fichier."""
        if item in self.selected_files:
            self.selected_files.remove(item)
            self.files_tree.item(item, text='☐')
        else:
            self.selected_files.add(item)
            self.files_tree.item(item, text='☑')

    def toggle_selection(self, event):
        """Gère la touche espace pour basculer la sélection."""
        selection = self.files_tree.selection()
        if selection:
            file_info = next((f for f in self.fit_files if f['name'] == self.files_tree.item(selection[0])['values'][0]), None)
            if file_info and not file_info['processed']:
                self.toggle_file_selection(selection[0])

    def handle_selection_action(self, action):
        """Gère les actions de sélection depuis le menu déroulant."""
        if action == "Tout sélectionner":
            self.select_all_files()
        elif action == "Tout désélectionner":
            self.deselect_all_files()
        self.selection_var.set("Actions...")

    def select_all_files(self):
        """Sélectionne tous les fichiers non traités."""
        self.selected_files.clear()
        for parent in self.files_tree.get_children():
            for child in self.files_tree.get_children(parent):
                file_info = next(f for f in self.fit_files if f['name'] == self.files_tree.item(child)['values'][0])
                if not file_info['processed']:
                    self.selected_files.add(child)
                    self.files_tree.item(child, text='☑')

    def deselect_all_files(self):
        """Désélectionne tous les fichiers."""
        for item in self.selected_files.copy():
            self.files_tree.item(item, text='☐')
        self.selected_files.clear()

    def upload_to_garmin(self):
        """Upload vers Garmin Connect."""
        if not self.is_connected:
            self.log("Vous devez être connecté à Garmin Connect", "warning")
            return
        if not self.selected_files:
            self.log("Aucun fichier sélectionné", "warning")
            return
        backup_path = get_backup_path()
        if not backup_path:
            self.log("Configurez un dossier de sauvegarde avant de continuer", "warning")
            return
        self.is_processing = True
        self.update_ui_state()
        self.log("Début de l'upload vers Garmin Connect...")
        
        selected_files = [next(f for f in self.fit_files if f['name'] == self.files_tree.item(fid)['values'][0])['path'] 
                         for fid in self.selected_files]
        
        threading.Thread(target=self.upload_worker, args=(selected_files, backup_path), daemon=True).start()

    def upload_worker(self, files: List[Path], backup_path: Path):
        """Worker pour l'upload."""
        try:
            total_count = len(files)
            processed_files = []
            temp_dir = Path.home() / ".fituploader_temp"
            temp_dir.mkdir(exist_ok=True)
            
            for i, file_path in enumerate(files):
                self.upload_queue.put(('progress', (i / total_count) * 100))
                self.upload_queue.put(('status', f"Traitement de {file_path.name}..."))
                
                new_filename = generate_new_filename(file_path)
                temp_file_path = temp_dir / new_filename
                backup_file = backup_path / new_filename
                
                if cleanup_fit_file(file_path, temp_file_path):
                    if backup_path:
                        temp_file_path.replace(backup_file)
                        self.upload_queue.put(('log', f"Fichier sauvegardé: {backup_file.name}", "success"))
                        cleanup_fit_file(file_path, temp_file_path)
                    processed_files.append((file_path, temp_file_path))
                
            self.upload_queue.put(('status', "Upload vers Garmin Connect..."))
            upload_results = upload_fit_files_to_garmin([temp_path for _, temp_path in processed_files])
            
            successful_uploads = []
            failed_uploads = []
            
            for (original_path, temp_path), success in zip(processed_files, 
                                                          [upload_results.get(temp_path, False) for _, temp_path in processed_files]):
                if success:
                    successful_uploads.append(original_path)
                    try:
                        temp_path.unlink()
                    except:
                        pass
                else:
                    failed_uploads.append(original_path)
                    try:
                        temp_path.unlink()
                    except:
                        pass
            
            if successful_uploads:
                for file_path in successful_uploads:
                    self.cleanup_original_file(file_path)
                self.upload_queue.put(('log', f"{len(successful_uploads)} fichier(s) uploadé(s) avec succès", "success"))
            
            if failed_uploads:
                self.upload_queue.put(('log', f"{len(failed_uploads)} fichier(s) ont échoué", "error"))
            
            cleanup_old_backup_files(backup_path)
            self.upload_queue.put(('progress', 100))
            self.upload_queue.put(('status', "Upload terminé"))
            self.upload_queue.put(('refresh', None))
            self.upload_queue.put(('done', None))
        
        except Exception as e:
            self.upload_queue.put(('log', f"Erreur durant le traitement: {str(e)}", "error"))
            self.upload_queue.put(('done', None))

    def cleanup_original_file(self, file_path: Path):
        """Nettoie un fichier original après upload réussi."""
        try:
            if file_path.exists():
                file_path.unlink()
                self.log(f"Fichier original supprimé: {file_path.name}", "success")
        except Exception as e:
            self.log(f"Erreur lors de la suppression de {file_path.name}: {e}", "error")

    def cleanup_uploaded(self):
        """Nettoyage manuel des fichiers uploadés."""
        sources = get_available_sources()
        if not sources:
            self.log("Aucune source configurée", "warning")
            return
        backup_path = get_backup_path()
        if not backup_path:
            self.log("Configurez un dossier de sauvegarde avant de continuer", "warning")
            return
        cleaned_count = 0
        for source_name, source_path in sources.items():
            if not source_path.is_dir():
                continue
            fit_files = get_fit_files(source_path)
            for fit_file in fit_files:
                if is_file_already_processed(fit_file):
                    try:
                        new_filename = generate_new_filename(fit_file)
                        backup_file = backup_path / new_filename
                        if cleanup_fit_file(fit_file, backup_file):
                            self.log(f"Fichier sauvegardé: {backup_file.name}", "success")
                        self.cleanup_original_file(fit_file)
                        cleaned_count += 1
                    except Exception as e:
                        self.log(f"Erreur lors du nettoyage de {fit_file.name}: {e}", "error")
        cleanup_old_backup_files(backup_path)
        self.scan_files()
        self.log(f"{cleaned_count} fichier(s) nettoyé(s)" if cleaned_count else "Aucun fichier à nettoyer", "success" if cleaned_count else "info")

    def check_queue(self):
        """Vérifie la queue pour les mises à jour de l'interface."""
        try:
            while True:
                msg_type, msg_data = self.upload_queue.get_nowait()
                if msg_type == 'progress':
                    self.progress_var.set(msg_data)
                elif msg_type == 'status':
                    self.status_label.configure(text=msg_data)
                elif msg_type == 'log':
                    self.log(*msg_data)
                elif msg_type == 'refresh':
                    self.scan_files()
                elif msg_type == 'done':
                    self.is_processing = False
                    self.update_ui_state()
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

    def log(self, message, level="info"):
        """Ajoute un message au journal."""
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n", level)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def clear_logs(self):
        """Vide le journal."""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")

    def format_size(self, size_bytes):
        """Formate la taille en bytes vers un format lisible."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"

    def on_closing(self):
        """Gestionnaire de fermeture de l'application."""
        config["sauvegarde_path"] = self.sauvegarde_path.get()
        if self.remember_email.get():
            config["username"] = self.email.get()
        save_config(config)
        self.destroy()

def main():
    app = FitUploaderApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()

if __name__ == "__main__":
    main()
