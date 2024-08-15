import os
import re
import logging
import configparser
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Optional
from datetime import datetime, timedelta
import pyperclip

# Setup logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('file_watcher.log'),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

PROCESSED_FILES = {}
IGNORE_INTERVAL = timedelta(seconds=60)  # Increase this interval as needed

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

def extract_number(filename: str) -> Optional[str]:
    """
    Extract the specific number from the filename.

    :param filename: The filename to extract the number from
    :return: The extracted number or None
    """
    match = re.search(r'AZ_[^_]+_.*?_(\\d+)_.*', filename)
    if match:
        return match.group(1)
    return None

def copy_to_clipboard(text: str):
    """
    Copy the given text to the clipboard.

    :param text: The text to copy to the clipboard
    """
    pyperclip.copy(text)
    logger.info(f"Copied to clipboard: {text}")

def confirm_print(file_path: str) -> bool:
    """
    Show a popup to confirm if the file should be printed.

    :param file_path: The path of the file to be printed.
    :return: True if the user confirms, False otherwise
    """
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    result = messagebox.askokcancel("Print Confirmation", f"Do you want to print the file:\\n\\n{file_path}?")
    root.destroy()
    return result

def print_file(file_path: str):
    """
    Print file using the default application only if user confirms.

    :param file_path: The path to the file to be printed.
    """
    try:
        logger.info(f"Asked to print file: {file_path}")
        if confirm_print(file_path):
            os.startfile(file_path, "print")
            logger.info(f"File sent to printer successfully: {file_path}")
        else:
            logger.info(f"Print cancelled for file: {file_path}")
    except Exception as e:
        logger.error(f"Failed to print file: {e}")

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
            number = extract_number(filename)
            if number:
                copy_to_clipboard(number)
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

def scan_existing_files(directory: str, search_pattern: str):
    """
    Scan the provided directory for files matching the search pattern and process them.
    
    :param directory: The directory to scan
    :param search_pattern: The pattern to search for in filenames
    """
    handler = Handler(search_pattern)
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            handler.process_file("Exists", file_path)

def main():
    config_file = r'src\\config_noGUI.ini'
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

    logger.info(f"Scanning existing files in directory '{watch_dir}' for pattern '{search_pattern}'")
    scan_existing_files(watch_dir, search_pattern)

    logger.info(f"Starting watcher: Directory '{watch_dir}', Pattern '{search_pattern}'")
    start_watcher(watch_dir, search_pattern)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error(f"An error occurred: {e}")