import os
import re
import logging
import configparser
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Optional
import win32print

# Setup logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('file_watcher.log'),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

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

def show_popup(file_path: str, num: str):
    """
    Show a popup to open the file.
    
    :param file_path: The path of the file
    :param num: The found pattern
    """
    def open_file():
        try:
            os.startfile(file_path)
        except Exception as e:
            logger.error(f"Error opening file: {e}")

    root = tk.Tk()
    root.withdraw()  # Hide the main window
    if messagebox.askyesno("File found", f"File with pattern '{num}' found. Do you want to open the file?\n\n{file_path}"):
        open_file()
    root.destroy()

def print_pattern(pattern: str):
    """
    Print a pattern using the default printer

    :param pattern: The pattern to print
    """
    printer_name = win32print.GetDefaultPrinter()
    if not printer_name:
        logger.error("No default printer found")
        return

    logger.info(f"Printing pattern '{pattern}' to printer '{printer_name}'")

    try:
        hPrinter = win32print.OpenPrinter(printer_name)
        doc_info = {
            "pDocName": "File Watcher Pattern Print",
            "pOutputFile": None,
            "pDatatype": "RAW"
        }
        hJob = win32print.StartDocPrinter(hPrinter, 1, (doc_info,))
        win32print.StartPagePrinter(hPrinter)

        win32print.WritePrinter(hPrinter, pattern.encode('utf-8'))

        win32print.EndPagePrinter(hPrinter)
        win32print.EndDocPrinter(hPrinter)
        win32print.ClosePrinter(hPrinter)
        logger.info("Pattern printed successfully")
    except Exception as e:
        logger.error(f"Failed to print pattern: {e}")

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
            self.observer.join()
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
        filename = os.path.basename(file_path)
        logger.info(f"{event_type} file: {filename} at path: {file_path}")
        num = contains_pattern(filename, self.search_pattern)
        if num:
            logger.info(f"File with pattern '{num}' found at path: {file_path}")
            if event_type != "Deleted":
                show_popup(file_path, num)
                print_pattern(num)  # Print the found pattern

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
    config_file = r'src\config_noGUI.ini'
    config = configparser.ConfigParser()
    
    logger.info(f"Reading config file: {config_file}")
    with open(config_file, 'r', encoding='utf-8') as f:
        config.read_file(f)
    
    ensure_config_exists(config, config_file)
    
    # Read settings from config file
    watch_dir = config.get('settings', 'watch_dir', fallback='')
    search_pattern = config.get('settings', 'search_pattern', fallback='')

    logger.info(f"Configured watch directory: '{watch_dir}'")
    logger.info(f"Configured search pattern: '{search_pattern}'")

    # Verify the directory exists
    if not os.path.isdir(watch_dir):
        logger.error(f"Directory does not exist: {watch_dir}")
        raise ValueError("Please provide a valid directory and search pattern in the config_noGUI.ini file.")

    logger.info(f"Starting watcher: Directory '{watch_dir}', Pattern '{search_pattern}'")
    start_watcher(watch_dir, search_pattern)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error(f"An error occurred: {e}")