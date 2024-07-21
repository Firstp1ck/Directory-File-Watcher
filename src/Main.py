import os
import re
import logging
import configparser
import tkinter as tk
from tkinter import messagebox, filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Optional
from datetime import datetime, timedelta

# Setup logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('file_watcher.log'),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

PROCESSED_FILES = {}
IGNORE_INTERVAL = timedelta(seconds=60)  # Time window to ignore subsequent events for the same file

def contains_pattern(filename: str, search_pattern: str) -> Optional[str]:
    """
    Check if the filename contains the search pattern.
    
    :param filename: The filename to check
    :param search_pattern: The pattern to search for
    :return: The found pattern or None
    """
    pattern = re.compile(search_pattern)
    match = pattern.search(filename)
    if match:
        logger.info(f"Match found: {filename}")
        return match.group(0)
    return None

def show_print_confirmation(file_path: str):
    """
    Show a popup to confirm that the print process is finished.

    :param file_path: The path of the file that was printed.
    """
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Print Confirmation", f"Print command issued for file:\n\n{file_path}")
    root.destroy()

def print_file(file_path: str):
    """
    Print a PDF, DOC, or Excel file using the default application.

    :param file_path: The path to the file to be printed.
    """
    try:
        logger.info(f"Printing file: {file_path}")
        os.startfile(file_path, "print")
        logger.info(f"File sent to printer successfully: {file_path}")
        show_print_confirmation(file_path)
    except Exception as e:
        logger.error(f"Failed to print file: {e}")
        show_print_confirmation(file_path)

class Watcher:
    def __init__(self, directory_to_watch: str, search_pattern: str):
        self.DIRECTORY_TO_WATCH = directory_to_watch
        self.search_pattern = search_pattern
        self.observer = Observer()

    def run(self):
        event_handler = Handler(self.search_pattern)
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        logger.info(f"Watching started on: {self.DIRECTORY_TO_WATCH} (including subdirectories)")
        try:
            while True:
                pass
        except KeyboardInterrupt:
            self.observer.stop()
            logger.info("Watching stopped")
        self.observer.join()

class Handler(FileSystemEventHandler):
    def __init__(self, search_pattern: str):
        super().__init__()
        self.search_pattern = search_pattern

    def process_file(self, event_type: str, file_path: str):
        """
        Process the file to check if it contains the search pattern.
        :param event_type: Type of file event
        :param file_path: Path of the file
        """
        global PROCESSED_FILES
        now = datetime.now()

        # Clean up the processed files dictionary
        PROCESSED_FILES = {path: timestamp for path, timestamp in PROCESSED_FILES.items() if now - timestamp < IGNORE_INTERVAL}

        # Check if the file was processed recently
        if file_path in PROCESSED_FILES:
            logger.info(f"Ignoring file as it was processed recently: {file_path}")
            return

        filename = os.path.basename(file_path)
        logger.info(f"{event_type} file: {filename} at path: {file_path}")
        num = contains_pattern(filename, self.search_pattern)
        if num:
            logger.info(f"File with pattern '{num}' found at path: {file_path}")
            if event_type != "Deleted":
                print_file(file_path)
                PROCESSED_FILES[file_path] = now  # Update the last processed time

    def on_created(self, event):
        if not event.is_directory:
            self.process_file("Created", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_file("Moved", event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file("Modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_file("Deleted", event.src_path)

def start_watcher(directory: str, search_pattern: str):
    w = Watcher(directory, search_pattern)
    w.run()

def browse_directory(entry_dir: tk.Entry):
    directory = filedialog.askdirectory()
    if directory:
        entry_dir.delete(0, tk.END)
        entry_dir.insert(0, directory)

def ensure_config_exists(config: configparser.ConfigParser, config_file: str):
    """
    Ensure that the config file exists and contains necessary defaults.
    :param config: The ConfigParser object
    :param config_file: The path to the config file
    """
    if not config.has_section('settings'):
        config.add_section('settings')
    if 'watch_dir' not in config['settings']:
        config.set('settings', 'watch_dir', '')
    if 'search_pattern' not in config['settings']:
        config.set('settings', 'search_pattern', '')
    with open(config_file, 'w', encoding='utf-8') as file:
        config.write(file)

def main():
    config_file = 'config.ini'
    config = configparser.ConfigParser()
    config.read(config_file)
    
    ensure_config_exists(config, config_file)

    root = tk.Tk()
    root.title("File Watcher")

    # Window Layout
    tk.Label(root, text="Directory to Watch:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
    entry_dir = tk.Entry(root, width=50)
    entry_dir.grid(row=0, column=1, padx=10, pady=5)
    tk.Button(root, text="Browse...", command=lambda: browse_directory(entry_dir)).grid(row=0, column=2, padx=10, pady=5)

    tk.Label(root, text="Search Pattern (Regex):").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
    entry_pattern = tk.Entry(root, width=50)
    entry_pattern.grid(row=1, column=1, padx=10, pady=5)

    # Load initial values from config.ini if available
    entry_dir.insert(0, config['settings']['watch_dir'])
    entry_pattern.insert(0, config['settings']['search_pattern'])

    def on_start():
        directory = entry_dir.get()
        search_pattern = entry_pattern.get()

        if not directory or not search_pattern:
            messagebox.showerror("Error", "Please provide a valid directory and search pattern.")
            return

        # Save settings in config.ini
        config['settings']['watch_dir'] = directory
        config['settings']['search_pattern'] = search_pattern

        with open(config_file, 'w') as configfile:
            config.write(configfile)

        root.destroy()  # Close window and start watcher
        logger.info(f"Starting watcher: Directory '{directory}', Pattern '{search_pattern}'")
        start_watcher(directory, search_pattern)

    tk.Button(root, text="Start", command=on_start).grid(row=2, column=1, pady=10)

    root.mainloop()

if __name__ == '__main__':
    main()