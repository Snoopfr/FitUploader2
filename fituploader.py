#!/usr/bin/env python3
"""
Application FitUploader - Version Améliorée
Usage: "python3 fituploader.py"
Description:
    - Interface graphique pour se connecter à Garmin Connect avec maintien de session.
    - Recherche et traitement automatique des fichiers FIT provenant de deux sources :
         • MyWhoosh (détecté automatiquement selon l'OS)
         • TrainingPeaks Virtual (répertoire configurable)
    - Auto‑détection fiable de la source à utiliser en fonction des fichiers FIT.
    - Possibilité d'uploader plusieurs fichiers à la fois.
    - Sauvegarde des fichiers traités dans un même dossier de backup avec prefix selon la source (MW_ ou TPV_).
    - Nettoyage automatique des fichiers traités avec succès.
    - Sauvegarde de l'email et des chemins de configuration dans le répertoire personnel.
    - Interface modernisée avec notifications intégrées et indicateurs de statut.
    - Session Garmin persistante avec renouvellement automatique.
Crédits:
    Basé sur le script original myWhoosh2Garmin.py.
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
from datetime import datetime, timedelta
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import importlib.util

# --- Configuration globale et journalisation ---
SCRIPT_DIR = Path(__file__).resolve().parent
LOG_FILE = SCRIPT_DIR / "FitUploader.log"
CONFIG_FILE = Path.home() / ".fituploader_config.json"
TOKENS_PATH = SCRIPT_DIR / ".garth"
INSTALLED_PACKAGES_FILE = SCRIPT_DIR / "installed_packages.json"
FILE_DIALOG_TITLE = "FitUploader"

# Constants pour les préfixes de fichiers
MW_PREFIX = "MW_"
TPV_PREFIX = "TPV_"
MYWHOOSH_PREFIX_WINDOWS = "TheWhooshGame"

# Configuration des couleurs pour l'interface moderne
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
        logger.debug("pip n'est pas disponible.")

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
    GarthException = Exception
    GarthHTTPError = Exception

# --- Fonctions utilitaires pour les fichiers FIT ---
def get_mywhoosh_directory() -> Path:
    """Retourne le chemin du répertoire MyWhoosh selon l'OS."""
    if os.name == "posix":  # macOS et Linux
        target = (Path.home() / "Library" / "Containers" / "com.whoosh.whooshgame" /
                  "Data" / "Library" / "Application Support" / "Epic" / "MyWhoosh" /
                  "Content" / "Data")
        if target.is_dir():
            return target
        else:
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
    else:
        logger.error("OS non supporté.")
        return Path()

def get_tp_directory() -> Optional[Path]:
    """Retourne le chemin du répertoire TrainingPeaks Virtual à partir de la config."""
    path = config.get("tp_directory", "")
    if path and Path(path).is_dir():
        return Path(path)
    return None

def get_backup_path() -> Optional[Path]:
    """Retourne le chemin de sauvegarde pour les fichiers traités."""
    path = config.get("backup_path", "")
    if path and Path(path).is_dir():
        return Path(path)
    return None

def calculate_avg(values: iter) -> int:
    return sum(values) / len(values) if values else 0

def append_value(values: List[int], message: object, field_name: str) -> None:
    value = getattr(message, field_name, None)
    values.append(value if value else 0)

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
    # Convertir les timestamps en objets datetime
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
    # Utiliser le nom du fichier et sa taille comme clé unique
    file_key = f"{file_path.name}_{file_path.stat().st_size}"
    processed_info[file_key] = datetime.now().isoformat()
    config["processed_files"] = processed_info
    save_config(config)

def is_file_already_processed(file_path: Path) -> bool:
    """Vérifie si un fichier a déjà été traité."""
    processed_info = get_processed_files_info()
    file_key = f"{file_path.name}_{file_path.stat().st_size}"
    return file_key in processed_info

def generate_new_filename(fit_file: Path, source: str) -> str:
    """Génère un nouveau nom de fichier avec préfixe selon la source et horodatage."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    prefix = MW_PREFIX if source == "MyWhoosh" else TPV_PREFIX
    
    match = re.search(r'MyNewActivity-(\d+)\.fit', fit_file.name)
    activity_num = f"_{match.group(1)}" if match else ""
    
    return f"{prefix}{timestamp}{activity_num}.fit"

def cleanup_old_backup_files(backup_dir: Path, max_files: int = 50) -> None:
    """Nettoie les anciens fichiers de sauvegarde pour éviter l'accumulation."""
    if not backup_dir.exists():
        return
    
    fit_files = list(backup_dir.glob("*.fit"))
    if len(fit_files) > max_files:
        # Trier par date de modification et supprimer les plus anciens
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
    
    # MyWhoosh
    myw_dir = get_mywhoosh_directory()
    if myw_dir and myw_dir.is_dir():
        sources["MyWhoosh"] = myw_dir
    
    # TrainingPeaks Virtual
    tp_dir = get_tp_directory()
    if tp_dir and tp_dir.is_dir():
        sources["TrainingPeaks Virtual"] = tp_dir
    
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

# --- Fonctions d'authentification améliorées ---
def authenticate_to_garmin_gui(email: str, password: str) -> bool:
    """Authentifie l'utilisateur sur Garmin Connect."""
    logger.info("Tentative d'authentification sur Garmin Connect...")
    try:
        garth.login(email, password)
        garth.save(TOKENS_PATH)
        
        # Sauvegarder la date de dernière authentification
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
        # Vérifier si le token est valide en faisant un appel test
        garth.client.username
        logger.info("Authentification par token réussie.")
        return True
    except Exception as e:
        logger.info(f"Token expiré ou invalide: {e}")
        # Supprimer le token invalide
        try:
            TOKENS_PATH.unlink()
        except:
            pass
        return False

def is_session_valid() -> bool:
    """Vérifie si la session Garmin est encore valide."""
    try:
        # Tenter un appel simple pour vérifier la validité
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
    """Upload les fichiers FIT vers Garmin Connect avec gestion des erreurs améliorée."""
    results = {}
    
    for file_path in files:
        try:
            if not file_path.exists():
                logger.error(f"Fichier inexistant: {file_path}")
                results[file_path] = False
                continue
            
            # Vérifier et rafraîchir la session si nécessaire
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
            
            # Marquer le fichier original comme traité
            save_processed_file_info(file_path)
            
            time.sleep(1)  # Éviter de surcharger l'API
            
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

# --- Gestionnaire de log pour l'interface graphique ---
class TextHandler(logging.Handler):
    def __init__(self, widget: tk.Text):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.widget.configure(state='normal')
            # Ajouter une couleur selon le niveau de log
            if record.levelno >= logging.ERROR:
                self.widget.insert(tk.END, msg + "\n", "error")
            elif record.levelno >= logging.WARNING:
                self.widget.insert(tk.END, msg + "\n", "warning")
            elif record.levelno >= logging.INFO:
                self.widget.insert(tk.END, msg + "\n", "info")
            else:
                self.widget.insert(tk.END, msg + "\n")
            
            self.widget.configure(state='disabled')
            self.widget.yview(tk.END)
        self.widget.after(0, append)

# --- Widget de notification intégré ---
class NotificationFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.notifications = []
        self.setup_ui()
    
    def setup_ui(self):
        self.columnconfigure(0, weight=1)
    
    def show_notification(self, message: str, type_: str = "info", duration: int = 5000):
        """Affiche une notification temporaire."""
        notification = ttk.Frame(self, relief="solid", borderwidth=1)
        notification.pack(fill="x", padx=5, pady=2)
        
        # Couleur selon le type
        colors = {
            "success": COLORS['success'],
            "error": COLORS['error'],
            "warning": COLORS['warning'],
            "info": COLORS['primary']
        }
        
        # Icône selon le type
        icons = {
            "success": "✓",
            "error": "✗",
            "warning": "⚠",
            "info": "ℹ"
        }
        
        # Conteneur pour l'icône et le message
        content_frame = ttk.Frame(notification)
        content_frame.pack(fill="x", padx=10, pady=5)
        
        icon_label = ttk.Label(content_frame, text=icons.get(type_, "ℹ"), 
                              foreground=colors.get(type_, COLORS['primary']),
                              font=("Arial", 12, "bold"))
        icon_label.pack(side="left", padx=(0, 10))
        
        msg_label = ttk.Label(content_frame, text=message, wraplength=600)
        msg_label.pack(side="left", fill="x", expand=True)
        
        # Bouton de fermeture
        close_btn = ttk.Button(content_frame, text="×", width=3,
                              command=lambda: self.close_notification(notification))
        close_btn.pack(side="right")
        
        self.notifications.append(notification)
        
        # Auto-fermeture après durée spécifiée
        if duration > 0:
            self.after(duration, lambda: self.close_notification(notification))
    
    def close_notification(self, notification):
        """Ferme une notification."""
        if notification in self.notifications:
            self.notifications.remove(notification)
            notification.destroy()
    
    def clear_all_notifications(self):
        """Ferme toutes les notifications."""
        for notification in self.notifications[:]:
            self.close_notification(notification)

# --- Application Tkinter modernisée ---
class FitUploaderApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FitUploader - Version Améliorée")
        self.geometry("850x900")
        self.resizable(True, True)
        self.configure(bg=COLORS['background'])
        
        # Variables d'état
        self.is_connected = False
        self.is_processing = False
        self.processed_count = 0
        self.total_count = 0
        
        # Initialisation
        self.setup_style()
        self.create_widgets()
        self.add_logging_handler()
        
        # Pré-remplir l'email si sauvegardé
        if config.get("username"):
            self.username_entry.insert(0, config["username"])
        
        # Tenter une authentification automatique
        self.auto_authenticate()
        
        # Démarrer la vérification périodique de session
        self.start_session_monitor()
    
    def setup_style(self):
        """Configure le style moderne de l'interface."""
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        
        # Configuration des polices
        base_font = ("Segoe UI", 10)
        heading_font = ("Segoe UI", 12, "bold")
        small_font = ("Segoe UI", 9)
        
        # Styles personnalisés
        self.style.configure("Title.TLabel", font=heading_font, foreground=COLORS['text'])
        self.style.configure("Subtitle.TLabel", font=base_font, foreground=COLORS['text_secondary'])
        self.style.configure("Success.TLabel", font=base_font, foreground=COLORS['success'])
        self.style.configure("Error.TLabel", font=base_font, foreground=COLORS['error'])
        self.style.configure("Warning.TLabel", font=base_font, foreground=COLORS['warning'])
        
        # Boutons personnalisés
        self.style.configure("Primary.TButton", font=base_font, 
                           foreground="white", background=COLORS['primary'], padding=8)
        self.style.map("Primary.TButton", background=[("active", "#1d4ed8")])
        
        self.style.configure("Success.TButton", font=base_font,
                           foreground="white", background=COLORS['success'], padding=8)
        self.style.map("Success.TButton", background=[("active", "#059669")])
        
        self.style.configure("Danger.TButton", font=base_font,
                           foreground="white", background=COLORS['error'], padding=8)
        self.style.map("Danger.TButton", background=[("active", "#dc2626")])
    
    def create_widgets(self):
        """Crée l'interface utilisateur moderne."""
        # Frame principal avec scrollbar
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Zone de notifications
        self.notification_frame = NotificationFrame(main_frame)
        self.notification_frame.pack(fill="x", pady=(0, 10))
        
        # Titre principal
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill="x", pady=(0, 20))
        
        title_label = ttk.Label(title_frame, text="FitUploader", style="Title.TLabel")
        title_label.pack(side="left")
        
        self.status_indicator = ttk.Label(title_frame, text="●", font=("Arial", 16), 
                                        foreground=COLORS['error'])
        self.status_indicator.pack(side="right")
        
        # Frame d'authentification
        self.create_auth_frame(main_frame)
        
        # Frame de configuration
        self.create_config_frame(main_frame)
        
        # Frame des fichiers disponibles
        self.create_files_frame(main_frame)
        
        # Frame d'opérations
        self.create_operations_frame(main_frame)
        
        # Zone de progression
        self.create_progress_frame(main_frame)
        
        # Zone de log
        self.create_log_frame(main_frame)
        
        # Initialiser l'affichage
        self.update_ui_state()
    
    def create_auth_frame(self, parent):
        """Crée la section d'authentification."""
        auth_frame = ttk.LabelFrame(parent, text="Authentification Garmin Connect", padding=15)
        auth_frame.pack(fill="x", pady=(0, 15))
        
        # Configuration de la grille
        auth_frame.columnconfigure(1, weight=1)
        
        # Email
        ttk.Label(auth_frame, text="Email:").grid(row=0, column=0, padx=(0, 10), pady=5, sticky="e")
        self.username_entry = ttk.Entry(auth_frame, font=("Segoe UI", 10))
        self.username_entry.grid(row=0, column=1, padx=(0, 10), pady=5, sticky="ew")
        
        # Mot de passe
        ttk.Label(auth_frame, text="Mot de passe:").grid(row=1, column=0, padx=(0, 10), pady=5, sticky="e")
        self.password_entry = ttk.Entry(auth_frame, show="*", font=("Segoe UI", 10))
        self.password_entry.grid(row=1, column=1, padx=(0, 10), pady=5, sticky="ew")
        
        # Options et boutons
        options_frame = ttk.Frame(auth_frame)
        options_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky="ew")
        options_frame.columnconfigure(1, weight=1)
        
        self.remember_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Se souvenir de mon email", 
                       variable=self.remember_var).pack(side="left")
        
        self.login_button = ttk.Button(options_frame, text="Se connecter", 
                                     command=self.login, style="Primary.TButton")
        self.login_button.pack(side="right", padx=(10, 0))
        
        # Statut de connexion
        self.conn_status_label = ttk.Label(auth_frame, text="Non connecté", style="Error.TLabel")
        self.conn_status_label.grid(row=3, column=0, columnspan=3, pady=(10, 0))
    
    def create_config_frame(self, parent):
        """Crée la section de configuration."""
        config_frame = ttk.LabelFrame(parent, text="Configuration", padding=15)
        config_frame.pack(fill="x", pady=(0, 15))
        
        # Dossier de sauvegarde
        backup_frame = ttk.Frame(config_frame)
        backup_frame.pack(fill="x", pady=(0, 10))
        backup_frame.columnconfigure(1, weight=1)
        
        ttk.Label(backup_frame, text="Sauvegarde:").pack(side="left")
        self.backup_label = ttk.Label(backup_frame, text="Non configuré", style="Warning.TLabel")
        self.backup_label.pack(side="left", padx=(10, 0), fill="x", expand=True)
        ttk.Button(backup_frame, text="Configurer", command=self.change_backup_path).pack(side="right")
        
        # TrainingPeaks Virtual
        tp_frame = ttk.Frame(config_frame)
        tp_frame.pack(fill="x", pady=(0, 10))
        tp_frame.columnconfigure(1, weight=1)
        
        ttk.Label(tp_frame, text="TrainingPeaks:").pack(side="left")
        self.tp_label = ttk.Label(tp_frame, text="Non configuré", style="Warning.TLabel")
        self.tp_label.pack(side="left", padx=(10, 0), fill="x", expand=True)
        ttk.Button(tp_frame, text="Configurer", command=self.change_tp_path).pack(side="right")
        
        # Sources détectées
        sources_frame = ttk.Frame(config_frame)
        sources_frame.pack(fill="x")
        
        ttk.Label(sources_frame, text="Sources détectées:", style="Subtitle.TLabel").pack(anchor="w")
        self.sources_text = tk.Text(sources_frame, height=3, state="disabled", 
                                   font=("Consolas", 9), bg=COLORS['surface'])
        self.sources_text.pack(fill="x", pady=(5, 0))
    
    def create_files_frame(self, parent):
        """Crée la section des fichiers disponibles."""
        files_frame = ttk.LabelFrame(parent, text="Fichiers FIT disponibles", padding=15)
        files_frame.pack(fill="x", pady=(0, 15))
        
        # Header avec compteurs
        header_frame = ttk.Frame(files_frame)
        header_frame.pack(fill="x", pady=(0, 10))
        
        self.files_count_label = ttk.Label(header_frame, text="Aucun fichier trouvé", style="Subtitle.TLabel")
        self.files_count_label.pack(side="left")
        
        refresh_btn = ttk.Button(header_frame, text="⟳ Actualiser", command=self.refresh_files)
        refresh_btn.pack(side="right")
        
        # Liste des fichiers avec checkboxes
        list_frame = ttk.Frame(files_frame)
        list_frame.pack(fill="both", expand=True)
        
        # Scrollable frame pour les fichiers
        canvas = tk.Canvas(list_frame, height=150, bg=COLORS['surface'])
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.files_canvas = canvas
        self.file_vars = {}  # Pour stocker les variables des checkboxes
        
        # Boutons de sélection
        select_frame = ttk.Frame(files_frame)
        select_frame.pack(fill="x", pady=(10, 0))
        
        ttk.Button(select_frame, text="Tout sélectionner", 
                  command=self.select_all_files).pack(side="left")
        ttk.Button(select_frame, text="Tout désélectionner", 
                  command=self.deselect_all_files).pack(side="left", padx=(10, 0))
        
        # Auto-sélection des nouveaux fichiers
        self.auto_select_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(select_frame, text="Auto-sélectionner les nouveaux fichiers", 
                       variable=self.auto_select_var).pack(side="right")
    
    def create_operations_frame(self, parent):
        """Crée la section des opérations."""
        ops_frame = ttk.LabelFrame(parent, text="Opérations", padding=15)
        ops_frame.pack(fill="x", pady=(0, 15))
        
        buttons_frame = ttk.Frame(ops_frame)
        buttons_frame.pack(fill="x")
        
        # Bouton principal d'upload
        self.upload_button = ttk.Button(buttons_frame, text="📤 Uploader les fichiers sélectionnés", 
                                       command=self.upload_selected_files, style="Success.TButton")
        self.upload_button.pack(side="left", padx=(0, 10))
        
        # Bouton de nettoyage manuel
        self.cleanup_button = ttk.Button(buttons_frame, text="🧹 Nettoyer les fichiers traités", 
                                        command=self.manual_cleanup)
        self.cleanup_button.pack(side="left", padx=(0, 10))
        
        # Options de nettoyage automatique
        options_frame = ttk.Frame(ops_frame)
        options_frame.pack(fill="x", pady=(10, 0))
        
        self.auto_cleanup_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Nettoyage automatique après upload", 
                       variable=self.auto_cleanup_var).pack(side="left")
        
        self.backup_before_cleanup_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Sauvegarder avant nettoyage", 
                       variable=self.backup_before_cleanup_var).pack(side="left", padx=(20, 0))
    
    def create_progress_frame(self, parent):
        """Crée la section de progression."""
        progress_frame = ttk.LabelFrame(parent, text="Progression", padding=15)
        progress_frame.pack(fill="x", pady=(0, 15))
        
        # Barre de progression
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                          maximum=100, length=400)
        self.progress_bar.pack(fill="x", pady=(0, 10))
        
        # Labels de statut
        status_frame = ttk.Frame(progress_frame)
        status_frame.pack(fill="x")
        status_frame.columnconfigure(1, weight=1)
        
        self.progress_label = ttk.Label(status_frame, text="Prêt", style="Subtitle.TLabel")
        self.progress_label.pack(side="left")
        
        self.file_counter_label = ttk.Label(status_frame, text="", style="Subtitle.TLabel")
        self.file_counter_label.pack(side="right")
    
    def create_log_frame(self, parent):
        """Crée la section des logs."""
        log_frame = ttk.LabelFrame(parent, text="Journal d'activité", padding=15)
        log_frame.pack(fill="both", expand=True)
        
        # Contrôles du log
        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill="x", pady=(0, 10))
        
        ttk.Button(log_controls, text="Effacer", command=self.clear_log).pack(side="left")
        
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_controls, text="Défilement automatique", 
                       variable=self.auto_scroll_var).pack(side="left", padx=(10, 0))
        
        # Zone de texte pour les logs
        log_text_frame = ttk.Frame(log_frame)
        log_text_frame.pack(fill="both", expand=True)
        
        self.log_text = tk.Text(log_text_frame, height=15, state="disabled", 
                               font=("Consolas", 9), bg=COLORS['surface'], 
                               wrap="word")
        log_scrollbar = ttk.Scrollbar(log_text_frame, orient="vertical", 
                                     command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        
        # Configuration des couleurs pour les logs
        self.log_text.tag_config("error", foreground=COLORS['error'])
        self.log_text.tag_config("warning", foreground=COLORS['warning'])
        self.log_text.tag_config("info", foreground=COLORS['primary'])
        self.log_text.tag_config("success", foreground=COLORS['success'])
        
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")
        
        # Initialiser l'affichage
        self.update_config_display()
        self.refresh_files()
    
    def add_logging_handler(self):
        """Ajoute un gestionnaire de log pour l'interface."""
        text_handler = TextHandler(self.log_text)
        text_handler.setFormatter(formatter)
        logger.addHandler(text_handler)
    
    def update_ui_state(self):
        """Met à jour l'état de l'interface utilisateur."""
        # Indicateur de statut de connexion
        if self.is_connected:
            self.status_indicator.configure(foreground=COLORS['success'])
            self.conn_status_label.configure(text="✓ Connecté à Garmin Connect", style="Success.TLabel")
            self.login_button.configure(text="Déconnecter", style="Danger.TButton")
        else:
            self.status_indicator.configure(foreground=COLORS['error'])
            self.conn_status_label.configure(text="✗ Non connecté", style="Error.TLabel")
            self.login_button.configure(text="Se connecter", style="Primary.TButton")
        
        # Activation/désactivation des boutons selon l'état
        state = "normal" if self.is_connected and not self.is_processing else "disabled"
        self.upload_button.configure(state=state)
        
        # Bouton de nettoyage toujours disponible
        cleanup_state = "disabled" if self.is_processing else "normal"
        self.cleanup_button.configure(state=cleanup_state)
    
    def auto_authenticate(self):
        """Tente une authentification automatique avec les tokens sauvegardés."""
        if try_token_auth():
            self.is_connected = True
            self.update_ui_state()
            self.notification_frame.show_notification(
                "Connexion automatique réussie !", "success", 3000)
            logger.info("Authentification automatique réussie")
        else:
            logger.info("Aucune session sauvegardée trouvée")
    
    def start_session_monitor(self):
        """Démarre la surveillance périodique de la session."""
        def check_session():
            if self.is_connected and not is_session_valid():
                # Tenter de renouveler la session
                if refresh_garmin_session():
                    self.notification_frame.show_notification(
                        "Session Garmin renouvelée automatiquement", "info", 2000)
                else:
                    self.is_connected = False
                    self.update_ui_state()
                    self.notification_frame.show_notification(
                        "Session Garmin expirée. Reconnexion nécessaire.", "warning")
            
            # Programmer la prochaine vérification dans 5 minutes
            self.after(300000, check_session)
        
        # Démarrer la vérification dans 1 minute
        self.after(60000, check_session)
    
    def login(self):
        """Gère la connexion/déconnexion."""
        if self.is_connected:
            # Déconnexion
            self.is_connected = False
            try:
                if TOKENS_PATH.exists():
                    TOKENS_PATH.unlink()
            except:
                pass
            self.update_ui_state()
            self.notification_frame.show_notification("Déconnecté de Garmin Connect", "info")
            logger.info("Déconnexion effectuée")
        else:
            # Connexion
            email = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            
            if not email or not password:
                self.notification_frame.show_notification(
                    "Veuillez saisir votre email et mot de passe", "warning")
                return
            
            # Désactiver le bouton pendant la connexion
            self.login_button.configure(state="disabled", text="Connexion...")
            
            def authenticate():
                success = authenticate_to_garmin_gui(email, password)
                
                def update_ui():
                    self.login_button.configure(state="normal")
                    if success:
                        self.is_connected = True
                        if self.remember_var.get():
                            config["username"] = email
                            save_config(config)
                        self.password_entry.delete(0, tk.END)  # Effacer le mot de passe
                        self.notification_frame.show_notification(
                            f"Connexion réussie pour {email}", "success")
                        logger.info(f"Connexion réussie pour {email}")
                    else:
                        self.notification_frame.show_notification(
                            "Échec de la connexion. Vérifiez vos identifiants.", "error")
                    
                    self.update_ui_state()
                
                self.after(0, update_ui)
            
            # Lancer l'authentification dans un thread séparé
            threading.Thread(target=authenticate, daemon=True).start()
    
    def change_backup_path(self):
        """Change le répertoire de sauvegarde."""
        path = filedialog.askdirectory(title="Sélectionner le dossier de sauvegarde")
        if path:
            config["backup_path"] = path
            save_config(config)
            self.update_config_display()
            self.notification_frame.show_notification(
                f"Dossier de sauvegarde configuré: {Path(path).name}", "success")
    
    def change_tp_path(self):
        """Change le répertoire TrainingPeaks Virtual."""
        path = filedialog.askdirectory(title="Sélectionner le dossier TrainingPeaks Virtual")
        if path:
            config["tp_directory"] = path
            save_config(config)
            self.update_config_display()
            self.refresh_files()
            self.notification_frame.show_notification(
                f"Dossier TrainingPeaks configuré: {Path(path).name}", "success")
    
    def update_config_display(self):
        """Met à jour l'affichage de la configuration."""
        # Backup path
        backup_path = get_backup_path()
        if backup_path:
            self.backup_label.configure(text=str(backup_path), style="Success.TLabel")
        else:
            self.backup_label.configure(text="Non configuré", style="Warning.TLabel")
        
        # TrainingPeaks path
        tp_path = get_tp_directory()
        if tp_path:
            self.tp_label.configure(text=str(tp_path), style="Success.TLabel")
        else:
            self.tp_label.configure(text="Non configuré", style="Warning.TLabel")
        
        # Sources détectées
        sources = get_available_sources()
        self.sources_text.configure(state="normal")
        self.sources_text.delete(1.0, tk.END)
        
        if sources:
            for source_name, source_path in sources.items():
                self.sources_text.insert(tk.END, f"✓ {source_name}: {source_path}\n", "success")
        else:
            self.sources_text.insert(tk.END, "Aucune source FIT détectée.\n", "warning")
        
        self.sources_text.configure(state="disabled")
    
    def refresh_files(self):
        """Actualise la liste des fichiers disponibles."""
        # Nettoyer l'ancienne liste
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.file_vars.clear()
        
        # Obtenir les fichiers disponibles
        sources = get_available_sources()
        new_files = get_new_fit_files(sources)
        
        if not new_files:
            ttk.Label(self.scrollable_frame, text="Aucun nouveau fichier FIT trouvé", 
                     style="Subtitle.TLabel").pack(pady=20)
            self.files_count_label.configure(text="Aucun fichier trouvé")
            return
        
        # Grouper par source
        files_by_source = {}
        for file_path, source in new_files:
            if source not in files_by_source:
                files_by_source[source] = []
            files_by_source[source].append(file_path)
        
        # Afficher les fichiers groupés par source
        for source_name, files in files_by_source.items():
            # Header de source
            source_frame = ttk.Frame(self.scrollable_frame)
            source_frame.pack(fill="x", padx=5, pady=(10, 5))
            
            ttk.Label(source_frame, text=f"📂 {source_name} ({len(files)} fichiers)", 
                     style="Title.TLabel").pack(side="left")
            
            # Fichiers de la source
            for file_path in files:
                file_frame = ttk.Frame(self.scrollable_frame)
                file_frame.pack(fill="x", padx=20, pady=2)
                
                var = tk.BooleanVar(value=self.auto_select_var.get())
                self.file_vars[file_path] = var
                
                checkbox = ttk.Checkbutton(file_frame, variable=var)
                checkbox.pack(side="left")
                
                # Informations du fichier
                file_info = f"{file_path.name}"
                try:
                    stat = file_path.stat()
                    size_mb = stat.st_size / (1024 * 1024)
                    mod_time = datetime.fromtimestamp(stat.st_mtime)
                    file_info += f" ({size_mb:.1f} MB, {mod_time.strftime('%d/%m/%Y %H:%M')})"
                except:
                    pass
                
                ttk.Label(file_frame, text=file_info, font=("Consolas", 9)).pack(side="left", 
                                                                                padx=(10, 0))
        
        # Mettre à jour le compteur
        total_files = len(new_files)
        self.files_count_label.configure(text=f"{total_files} nouveau(x) fichier(s) trouvé(s)")
        
        # Log
        logger.info(f"{total_files} nouveaux fichiers FIT détectés")
        
        # Notification si nouveaux fichiers
        if total_files > 0:
            self.notification_frame.show_notification(
                f"{total_files} nouveau(x) fichier(s) FIT détecté(s)", "info", 3000)
    
    def select_all_files(self):
        """Sélectionne tous les fichiers."""
        for var in self.file_vars.values():
            var.set(True)
    
    def deselect_all_files(self):
        """Désélectionne tous les fichiers."""
        for var in self.file_vars.values():
            var.set(False)
    
    def get_selected_files(self) -> List[Path]:
        """Retourne la liste des fichiers sélectionnés."""
        return [file_path for file_path, var in self.file_vars.items() if var.get()]
    
    def upload_selected_files(self):
        """Upload les fichiers sélectionnés vers Garmin Connect."""
        if not self.is_connected:
            self.notification_frame.show_notification(
                "Vous devez être connecté à Garmin Connect", "warning")
            return
        
        selected_files = self.get_selected_files()
        if not selected_files:
            self.notification_frame.show_notification(
                "Aucun fichier sélectionné", "warning")
            return
        
        # Vérifier si un dossier de sauvegarde est configuré
        backup_path = get_backup_path()
        if not backup_path and self.backup_before_cleanup_var.get():
            self.notification_frame.show_notification(
                "Configurez un dossier de sauvegarde avant de continuer", "warning")
            return
        
        self.is_processing = True
        self.total_count = len(selected_files)
        self.processed_count = 0
        self.update_ui_state()
        
        # Mise à jour des labels de progression
        self.progress_label.configure(text="Préparation des fichiers...")
        self.file_counter_label.configure(text=f"0/{self.total_count}")
        self.progress_var.set(0)
        
        def process_files():
            try:
                processed_files = []
                backup_files = []
                
                for i, file_path in enumerate(selected_files):
                    # Mise à jour de la progression dans l'interface
                    def update_progress(current=i, file_name=file_path.name):
                        progress = (current / self.total_count) * 100
                        self.progress_var.set(progress)
                        self.progress_label.configure(text=f"Traitement: {file_name}")
                        self.file_counter_label.configure(text=f"{current}/{self.total_count}")
                    
                    self.after(0, update_progress)
                    
                    try:
                        # Détecter la source du fichier
                        sources = get_available_sources()
                        source_name = None
                        for src_name, src_path in sources.items():
                            if file_path.parent == src_path:
                                source_name = src_name
                                break
                        
                        if not source_name:
                            source_name = "Unknown"
                        
                        # Créer le fichier nettoyé dans un répertoire temporaire
                        temp_dir = Path.home() / ".fituploader_temp"
                        temp_dir.mkdir(exist_ok=True)
                        
                        new_filename = generate_new_filename(file_path, source_name)
                        temp_file_path = temp_dir / new_filename
                        
                        # Nettoyer le fichier FIT
                        if cleanup_fit_file(file_path, temp_file_path):
                            # Sauvegarder une copie si demandé
                            if self.backup_before_cleanup_var.get() and backup_path:
                                backup_file = backup_path / new_filename
                                temp_file_path.replace(backup_file)
                                backup_files.append(backup_file)
                                logger.info(f"Fichier sauvegardé: {backup_file.name}")
                                
                                # Recréer le fichier temporaire pour l'upload
                                cleanup_fit_file(file_path, temp_file_path)
                            
                            processed_files.append((file_path, temp_file_path))
                        else:
                            logger.error(f"Échec du nettoyage de {file_path.name}")
                    
                    except Exception as e:
                        logger.error(f"Erreur lors du traitement de {file_path.name}: {e}")
                
                # Upload des fichiers traités
                if processed_files:
                    def update_upload_progress():
                        self.progress_label.configure(text="Upload vers Garmin Connect...")
                    self.after(0, update_upload_progress)
                    
                    temp_files = [temp_path for _, temp_path in processed_files]
                    upload_results = upload_fit_files_to_garmin(temp_files)
                    
                    # Analyser les résultats
                    successful_uploads = []
                    failed_uploads = []
                    
                    for (original_path, temp_path), success in zip(processed_files, 
                                                                  [upload_results.get(temp_path, False) 
                                                                   for _, temp_path in processed_files]):
                        if success:
                            successful_uploads.append(original_path)
                        else:
                            failed_uploads.append(original_path)
                        
                        # Nettoyer le fichier temporaire
                        try:
                            temp_path.unlink()
                        except:
                            pass
                    
                    # Nettoyage automatique des fichiers uploadés avec succès
                    if successful_uploads and self.auto_cleanup_var.get():
                        for file_path in successful_uploads:
                            self.cleanup_original_file(file_path)
                    
                    # Mise à jour finale de l'interface
                    def final_update():
                        self.is_processing = False
                        self.progress_var.set(100)
                        self.progress_label.configure(text="Terminé")
                        self.file_counter_label.configure(text=f"{len(successful_uploads)}/{self.total_count} réussis")
                        self.update_ui_state()
                        
                        # Notifications finales
                        if successful_uploads:
                            self.notification_frame.show_notification(
                                f"{len(successful_uploads)} fichier(s) uploadé(s) avec succès", 
                                "success", 5000)
                        
                        if failed_uploads:
                            self.notification_frame.show_notification(
                                f"{len(failed_uploads)} fichier(s) ont échoué", 
                                "error", 5000)
                        
                        # Actualiser la liste des fichiers
                        self.refresh_files()
                        
                        # Nettoyer les anciens fichiers de sauvegarde
                        if backup_path:
                            cleanup_old_backup_files(backup_path)
                    
                    self.after(0, final_update)
                
                else:
                    def no_files_update():
                        self.is_processing = False
                        self.progress_label.configure(text="Aucun fichier traité")
                        self.update_ui_state()
                        self.notification_frame.show_notification(
                            "Aucun fichier n'a pu être traité", "warning")
                    
                    self.after(0, no_files_update)
            
            except Exception as e:
                def error_update():
                    self.is_processing = False
                    self.progress_label.configure(text="Erreur")
                    self.update_ui_state()
                    self.notification_frame.show_notification(
                        f"Erreur durant le traitement: {str(e)}", "error")
                    logger.error(f"Erreur durant le traitement: {e}")
                
                self.after(0, error_update)
        
        # Lancer le traitement dans un thread séparé
        threading.Thread(target=process_files, daemon=True).start()
    
    def cleanup_original_file(self, file_path: Path):
        """Nettoie (supprime) un fichier original après upload réussi."""
        try:
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Fichier original supprimé: {file_path.name}")
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de {file_path.name}: {e}")
    
    def manual_cleanup(self):
        """Nettoyage manuel des fichiers traités."""
        sources = get_available_sources()
        if not sources:
            self.notification_frame.show_notification(
                "Aucune source configurée", "warning")
            return
        
        cleaned_count = 0
        
        for source_name, source_path in sources.items():
            if not source_path.is_dir():
                continue
            
            fit_files = get_fit_files(source_path)
            for fit_file in fit_files:
                if is_file_already_processed(fit_file):
                    try:
                        # Sauvegarder si demandé
                        backup_path = get_backup_path()
                        if backup_path and self.backup_before_cleanup_var.get():
                            new_filename = generate_new_filename(fit_file, source_name)
                            backup_file = backup_path / new_filename
                            
                            if cleanup_fit_file(fit_file, backup_file):
                                logger.info(f"Fichier sauvegardé: {backup_file.name}")
                        
                        # Supprimer l'original
                        self.cleanup_original_file(fit_file)
                        cleaned_count += 1
                    
                    except Exception as e:
                        logger.error(f"Erreur lors du nettoyage de {fit_file.name}: {e}")
        
        if cleaned_count > 0:
            self.notification_frame.show_notification(
                f"{cleaned_count} fichier(s) nettoyé(s)", "success")
            self.refresh_files()
        else:
            self.notification_frame.show_notification(
                "Aucun fichier à nettoyer", "info")
    
    def clear_log(self):
        """Efface le contenu du journal."""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")

# --- Point d'entrée principal ---
def main():
    """Point d'entrée principal de l'application."""
    try:
        app = FitUploaderApp()
        
        # Gestionnaire de fermeture propre
        def on_closing():
            logger.info("Fermeture de l'application")
            app.destroy()
        
        app.protocol("WM_DELETE_WINDOW", on_closing)
        
        # Démarrer l'application
        logger.info("=== Démarrage de FitUploader ===")
        app.mainloop()
        
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        print(f"Erreur fatale: {e}")

if __name__ == "__main__":
    main()
