import os
import re
import logging
import threading
import configparser
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Optional
from datetime import datetime, timedelta
import pyperclip

# Configure logging
def setup_logging(log_file: str = 'file_watcher.log'):
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_file),
                            logging.StreamHandler()
                        ])
    return logging.getLogger(__name__)

logger = setup_logging()

# Constants
PROCESSED_FILES = {}
IGNORE_INTERVAL = timedelta(seconds=60)  # Increase this interval as needed

# --- Utility Functions ---

def contains_patterns(filename: str, search_patterns: list[str]) -> Optional[str]:
    for pattern in search_patterns:
        match = re.search(pattern, filename)
        if match:
            logger.info(f"Pattern match found: {filename} (pattern: {pattern})")
            return match.group(0)
    return None

def extract_number(filename: str) -> Optional[str]:
    match = re.search(r'AZ_[^_]+_.*?_(\d+)_.*', filename)
    if match:
        return match.group(1)
    return None

def copy_to_clipboard(text: str):
    pyperclip.copy(text)
    logger.info(f"Copied to clipboard: {text}")

def confirm_print(file_path: str) -> bool:
    root = tk.Tk()
    root.withdraw()
    result = messagebox.askokcancel("Print Confirmation", f"Do you want to print the file:\n\n{file_path}?")
    root.destroy()
    return result

def print_file(file_path: str):
    try:
        logger.info(f"Asked to print file: {file_path}")
        if confirm_print(file_path):
            os.startfile(file_path, "print")
            logger.info(f"File sent to printer successfully: {file_path}")
        else:
            logger.info(f"Print cancelled for file: {file_path}")
    except Exception as e:
        logger.error(f"Failed to print file: {e}")

# --- File Handling Classes ---

class FileHandler:
    def __init__(self, search_patterns: list[str]):
        self.search_patterns = search_patterns

    def process_file(self, event_type: str, file_path: str):
        global PROCESSED_FILES
        now = datetime.now()

        # Clean up processed files dictionary
        PROCESSED_FILES = {path: timestamp for path, timestamp in PROCESSED_FILES.items() 
                           if now - timestamp < IGNORE_INTERVAL}

        # Check if file was processed recently
        if file_path in PROCESSED_FILES:
            logger.info(f"Ignoring recently processed file: {file_path}")
            return

        filename = os.path.basename(file_path)
        logger.info(f"{event_type} file: {filename} at path: {file_path}")
        
        pattern_match = contains_patterns(filename, self.search_patterns)
        if pattern_match:
            number = extract_number(filename)
            if number:
                copy_to_clipboard(number)
            logger.info(f"File with pattern '{pattern_match}' found at path: {file_path}")
            if event_type != "Deleted":
                print_file(file_path)
                PROCESSED_FILES[file_path] = now

# --- Watcher Setup ---

class Watcher:
    def __init__(self, directory_to_watch: str, file_handler: FileHandler):
        self.DIRECTORY_TO_WATCH = directory_to_watch
        self.file_handler = file_handler
        self.observer = Observer()

    def run(self):
        event_handler = EventHandler(self.file_handler)
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        self.observer.start()
        logger.info(f"Watching started on: {self.DIRECTORY_TO_WATCH} (including subdirectories)")
        try:
            self.observer.join()
        except KeyboardInterrupt:
            self.observer.stop()
            logger.info("Watching stopped due to keyboard interrupt")
        self.observer.join()

class EventHandler(FileSystemEventHandler):
    def __init__(self, file_handler: FileHandler):
        super().__init__()
        self.file_handler = file_handler

    def on_created(self, event):
        if not event.is_directory:
            self.file_handler.process_file('Created', event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.file_handler.process_file('Moved', event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.file_handler.process_file('Modified', event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.file_handler.process_file('Deleted', event.src_path)

# --- Configuration Management ---

def ensure_config_exists(config: configparser.ConfigParser, config_file: str):
    config_changed = False
    if not config.has_section('settings'):
        config.add_section('settings')
        config_changed = True
    
    if 'watch_dir' not in config['settings']:
        config.set('settings', 'watch_dir', '')
        config_changed = True
    
    if 'search_patterns' not in config['settings']:
        config.set('settings', 'search_patterns', '')
        config_changed = True

    if config_changed:
        with open(config_file, 'w', encoding='utf-8') as file:
            config.write(file)
        logger.info(f"Configuration defaults set in {config_file}")

def read_config(config_file: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        logger.info(f"Reading existing config file: {config_file}")
        with open(config_file, 'r', encoding='utf-8') as f:
            config.read_file(f)
    else:
        logger.info(f"No config file found. Creating defaults at {config_file}")
    return config

# --- Main Functionality ---

def scan_existing_files(directory: str, file_handler: FileHandler):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_handler.process_file("Exists", file_path)

def main():
    config_file = r'src/config_noGUI.ini'
    config = read_config(config_file)
    ensure_config_exists(config, config_file)
    config.read(config_file)

    watch_dir = config.get('settings', 'watch_dir', fallback='')
    search_patterns_str = config.get('settings', 'search_patterns', fallback='')
    search_patterns = [pattern.strip() for pattern in search_patterns_str.split(',') if pattern.strip()]

    logger.info(f"Using watch directory: {watch_dir}")
    logger.info(f"Using search patterns: {search_patterns}")

    if not os.path.isdir(watch_dir):
        logger.error(f"Directory does not exist: {watch_dir}")
        raise ValueError("Please provide a valid directory in the config_noGUI.ini file.")
    
    if not search_patterns:
        logger.error("No search patterns provided")
        raise ValueError("Please provide at least one search pattern in the config_noGUI.ini file.")

    logger.info(f"Scanning files in: {watch_dir}")
    file_handler = FileHandler(search_patterns)
    scan_existing_files(watch_dir, file_handler)

    logger.info("Starting file watcher")
    watcher = Watcher(watch_dir, file_handler)
    watcher.run()

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
