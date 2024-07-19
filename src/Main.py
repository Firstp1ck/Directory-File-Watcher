import os
import re
import logging
import configparser
import tkinter as tk
from tkinter import messagebox, filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Optional

# Logging einrichten
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('file_watcher.log'),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

# Regex-Muster für die 10-stellige Nummer
pattern = re.compile(r'\b\d{10}\b')

def contains_pattern(filename: str, search_pattern: str) -> Optional[str]:
    """
    Überprüft, ob der Dateiname das Suchmuster enthält.
    
    :param filename: Der zu überprüfende Dateiname
    :param search_pattern: Das zu suchende Muster
    :return: Das gefundene Muster oder None
    """
    if search_pattern in filename:
        logger.info(f"Match gefunden: {filename}")
        return search_pattern
    return None

def show_popup(file_path: str, num: str):
    """
    Zeigt ein Popup an, mit dem die Datei geöffnet werden kann.
    
    :param file_path: Der Pfad der Datei
    :param num: Die gefundene 10-stellige Nummer
    """
    def open_file():
        try:
            os.startfile(file_path)
        except Exception as e:
            logger.error(f"Fehler beim Öffnen der Datei: {e}")

    root = tk.Tk()
    root.withdraw()  # Versteckt das Hauptfenster
    if messagebox.askyesno("Datei gefunden", f"Datei mit Nummer '{num}' gefunden. Möchten Sie die Datei öffnen?\n\n{file_path}"):
        open_file()
    root.destroy()

class Watcher:
    def __init__(self, directory_to_watch: str, search_pattern: str):
        self.DIRECTORY_TO_WATCH = directory_to_watch
        self.search_pattern = search_pattern
        self.observer = Observer()

    def run(self):
        event_handler = Handler(self.search_pattern)
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=False)
        self.observer.start()
        logger.info(f"Überwachung gestartet auf: {self.DIRECTORY_TO_WATCH}")
        try:
            while True:
                pass
        except KeyboardInterrupt:
            self.observer.stop()
            logger.info("Beobachtung beendet")
        self.observer.join()

class Handler(FileSystemEventHandler):
    def __init__(self, search_pattern: str):
        super().__init__()
        self.search_pattern = search_pattern

    def process_file(self, event_type: str, file_path: str):
        """
        Verarbeitet die Datei und prüft, ob die Datei das Suchmuster enthält.
        :param event_type: Art des Datei-Events
        :param file_path: Pfad der Datei
        """
        filename = os.path.basename(file_path)
        logger.info(f"{event_type} Datei: {filename}")
        num = contains_pattern(filename, self.search_pattern)
        if num:
            logger.info(f"Gefundene Datei mit Nummer '{num}': {file_path}")
            show_popup(file_path, num)

    def on_created(self, event):
        if not event.is_directory:
            self.process_file("Erstellt", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_file("Umbenannt", event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file("Geändert", event.src_path)

def start_watcher(directory: str, search_pattern: str):
    w = Watcher(directory, search_pattern)
    w.run()

def browse_directory(entry_dir: tk.Entry):
    directory = filedialog.askdirectory()
    if directory:
        entry_dir.delete(0, tk.END)
        entry_dir.insert(0, directory)

def ensure_config_exists(config: configparser.ConfigParser, config_file: str):
    if 'settings' not in config:
        config['settings'] = {
            'watch_dir': '',
            'search_number': ''
        }
        with open(config_file, 'w') as file:
            config.write(file)

def main():
    config_file = 'config.ini'
    config = configparser.ConfigParser()
    config.read(config_file)
    
    ensure_config_exists(config, config_file)
    
    root = tk.Tk()
    root.title("Datei Überwacher")

    # Fenster Layout
    tk.Label(root, text="Ordner zum Überwachen:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
    entry_dir = tk.Entry(root, width=50)
    entry_dir.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(root, text="Durchsuchen...", command=lambda: browse_directory(entry_dir)).grid(row=0, column=2, padx=10, pady=5)

    tk.Label(root, text="Zu suchende 10-stellige Nummer:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
    entry_num = tk.Entry(root, width=50)
    entry_num.grid(row=1, column=1, padx=10, pady=5)

    # Initiale Werte aus config.ini laden, falls vorhanden
    entry_dir.insert(0, config['settings']['watch_dir'])
    entry_num.insert(0, config['settings']['search_number'])

    def on_start():
        directory = entry_dir.get()
        search_pattern = entry_num.get()

        if not directory or not search_pattern or not re.match(r'\b\d{10}\b', search_pattern):
            messagebox.showerror("Fehler", "Bitte geben Sie einen gültigen Ordner und eine 10-stellige Nummer an.")
            return

        # Einstellungen in config.ini speichern
        config['settings']['watch_dir'] = directory
        config['settings']['search_number'] = search_pattern

        with open(config_file, 'w') as configfile:
            config.write(configfile)

        root.destroy()  # Fenster schließen und Watcher starten
        logger.info(f"Überwachung starten: Ordner '{directory}', Muster '{search_pattern}'")
        start_watcher(directory, search_pattern)

    tk.Button(root, text="Start", command=on_start).grid(row=2, column=1, pady=10)

    root.mainloop()

if __name__ == '__main__':
    main()