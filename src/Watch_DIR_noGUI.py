import os
import re
import logging
import threading
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta
import pyperclip
import configparser
from typing import Optional
import modules as m

# --- Configure Logging ---
def setup_logging(log_file: str = 'file_watcher.log'):
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_file),
                            logging.StreamHandler()
                        ])
    return logging.getLogger(__name__)

logger = setup_logging()

# --- Constants ---
PROCESSED_FILES = {}
IGNORE_INTERVAL = timedelta(seconds=60)  # Increase this interval as needed


# --- Utility Functions ---

def contains_patterns(filename: str, search_patterns: list[str]) -> Optional[str]:
    """Check if any of the search patterns match the filename."""
    for pattern in search_patterns:
        try:
            match = re.search(pattern, filename)
            if match:
                logger.info(f"Pattern match found: {filename} (pattern: {pattern})")
                return match.group(0)
        except re.error as e:
            logger.error(f"Invalid regex pattern detected: {e}")
            continue
    return None


def extract_number(filename: str) -> Optional[str]:
    """Extract a number from the filename based on a specific pattern."""
    match = re.search(r'AZ_[^_]+_.*?_(\d+)_.*', filename)
    if match:
        return match.group(1)
    return None


def copy_to_clipboard(text: str):
    """Copy the extracted text to the system clipboard."""
    pyperclip.copy(text)
    logger.info(f"Copied to clipboard: {text}")


def confirm_print(file_path: str) -> bool:
    """Ask the user for confirmation to print a file using a Tkinter dialog."""
    root = tk.Tk()
    root.withdraw()
    result = messagebox.askokcancel("Print Confirmation", f"Do you want to print the file:\n\n{file_path}?")
    root.destroy()
    return result


def print_file(file_path: str):
    """Send the file to the printer if printing is confirmed."""
    try:
        logger.info(f"Asked to print file: {file_path}")
        if confirm_print(file_path):
            os.startfile(file_path, "print")  # Windows-specific command for printing
            logger.info(f"File sent to printer successfully: {file_path}")
        else:
            logger.info(f"Print cancelled for file: {file_path}")
    except FileNotFoundError as fnf_error:
        logger.error(f"File not found during print operation: {fnf_error}")
    except PermissionError as perm_error:
        logger.error(f"Permission error during print: {perm_error}")
    except Exception as general_error:
        logger.error(f"Failed to print file: {general_error}")


# --- File Handling Classes ---

class FileHandler:
    """Processes the files based on the given search patterns."""

    def __init__(self, search_patterns: list[str]):
        self.search_patterns = search_patterns

    def process_file(self, event_type: str, file_path: str):
        global PROCESSED_FILES
        now = datetime.now()
        
        # Clean up processed files dictionary by removing old entries
        PROCESSED_FILES = {path: timestamp for path, timestamp in PROCESSED_FILES.items()
                           if now - timestamp < IGNORE_INTERVAL}

        if file_path in PROCESSED_FILES:
            logger.info(f"Ignoring recently processed file: {file_path}")
            return

        filename = os.path.basename(file_path)
        logger.info(f"{event_type} file: {filename} at path: {file_path}")

        # Search for patterns in the filename
        pattern_match = contains_patterns(filename, self.search_patterns)
        if pattern_match:
            number = extract_number(filename)
            if number:
                copy_to_clipboard(number)
            if event_type != "Deleted":
                print_file(file_path)
                PROCESSED_FILES[file_path] = now


# --- Watcher Classes ---

class EventHandler(FileSystemEventHandler):
    """Handles file system events and delegates file processing."""

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


class Watcher:
    """Sets up the directory watcher using Watchdog."""

    def __init__(self, directory_to_watch: str, file_handler: FileHandler):
        self.DIRECTORY_TO_WATCH = directory_to_watch
        self.file_handler = file_handler
        self.observer = Observer()

    def run(self):
        event_handler = EventHandler(self.file_handler)
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=True)
        logger.info(f"Watching started on: {self.DIRECTORY_TO_WATCH} (including subdirectories)")
        
        try:
            watch_thread = threading.Thread(target=self._start_observer)
            watch_thread.start()  # Start the Observer in a separate thread for non-blocking operations
            watch_thread.join()
        except KeyboardInterrupt:
            self.observer.stop()
            logger.info("Watching stopped by KeyboardInterrupt.")
        finally:
            self.observer.join()

    def _start_observer(self):
        """Run the observer in the current thread."""
        self.observer.start()


# --- Utility Functions ---

def validate_inputs(watch_dir: str, search_patterns: list[str]):
    """Validate that the directory and regex patterns are valid."""
    # Validate directory
    if not os.path.isdir(watch_dir):
        raise ValueError(f"Watch Directory provided is invalid: {watch_dir}")

    # Validate each regex pattern
    for pattern in search_patterns:
        try:
            re.compile(pattern)  # Checks if the regex pattern is valid
        except re.error as e:
            raise ValueError(f"Invalid regex pattern provided: {pattern}. Error: {e}")


def scan_existing_files(directory: str, file_handler: FileHandler):
    """Scan existing files in the watched directory at startup."""
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_handler.process_file("Exists", file_path)


# --- Main Execution ---

def main():
    config_file = r'src/config_noGUI.ini'
    
    # Read and ensure the config exists
    config = m.read_config(config_file)
    m.ensure_config_exists(config, config_file)
    config.read(config_file)

    # Read the directory and search patterns from the config
    watch_dir = config.get('settings', 'watch_dir', fallback='')
    search_patterns_str = config.get('settings', 'search_patterns', fallback='')
    search_patterns = [pattern.strip() for pattern in search_patterns_str.split(',') if pattern.strip()]

    logger.info(f"Configured watch directory: {watch_dir}")
    logger.info(f"Configured search patterns: {search_patterns}")

    # Validate inputs
    try:
        validate_inputs(watch_dir, search_patterns)
    except ValueError as e:
        logger.error(f"Input validation error: {e}")
        raise

    # Create a FileHandler instance
    file_handler = FileHandler(search_patterns)
    
    # Scan existing files on startup
    logger.info(f"Scanning for existing files in the directory: {watch_dir}")
    scan_existing_files(watch_dir, file_handler)

    # Start the watcher
    logger.info("Starting file monitoring...")
    watcher = Watcher(watch_dir, file_handler)
    watcher.run()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")