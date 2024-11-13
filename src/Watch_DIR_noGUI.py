import os
import re
import logging
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta
import pyperclip
import configparser
from typing import Optional
import queue
import modules as m

# --- Message Queue for Thread Communication ---
message_queue = queue.Queue()

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


# --- Status Window Class ---

class StatusWindow:
    """Provides a GUI window to display the program's status."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("File Watcher Status")
        self.root.geometry("800x300")
        
        # Configure grid weights
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Status label
        self.status_label = tk.Label(self.root, text="Status: Initializing...",
                                   font=("Arial", 10, "bold"))
        self.status_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        # Activity log text widget
        self.log_frame = ttk.Frame(self.root)
        self.log_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        self.log_text = tk.Text(self.log_frame, height=10, width=45)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar for log text
        scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical", 
                                command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        # Statistics frame
        self.stats_frame = ttk.LabelFrame(self.root, text="Statistics")
        self.stats_frame.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        
        self.files_processed_label = tk.Label(self.stats_frame, 
                                            text="Files Processed: 0")
        self.files_processed_label.pack(pady=5)
        
        self.files_printed_label = tk.Label(self.stats_frame, 
                                          text="Files Printed: 0")
        self.files_printed_label.pack(pady=5)
        
        # Initialize counters
        self.files_processed = 0
        self.files_printed = 0

        # Setup periodic check for messages
        self.check_messages()

    def check_messages(self):
        """Check for messages in the queue and process them."""
        try:
            while True:  # Process all available messages
                message = message_queue.get_nowait()
                message_type = message.get('type')
                content = message.get('content')

                if message_type == 'status':
                    self.update_status(content)
                elif message_type == 'log':
                    self.add_log_entry(content)
                elif message_type == 'increment_processed':
                    self.increment_processed()
                elif message_type == 'increment_printed':
                    self.increment_printed()
        except queue.Empty:
            pass
        finally:
            # Schedule next check
            self.root.after(100, self.check_messages)
        
    def update_status(self, status: str):
        """Update the status label."""
        self.status_label.config(text=f"Status: {status}")
        
    def add_log_entry(self, message: str):
        """Add a new entry to the log text widget."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        
    def increment_processed(self):
        """Increment the processed files counter."""
        self.files_processed += 1
        self.files_processed_label.config(
            text=f"Files Processed: {self.files_processed}")
        
    def increment_printed(self):
        """Increment the printed files counter."""
        self.files_printed += 1
        self.files_printed_label.config(
            text=f"Files Printed: {self.files_printed}")


# --- File Handling Classes ---

class FileHandler:
    def __init__(self, search_patterns: list[str]):
        self.search_patterns = search_patterns

    def process_file(self, event_type: str, file_path: str):
        global PROCESSED_FILES
        now = datetime.now()
        
        # Update status through queue
        message_queue.put({'type': 'status', 
                          'content': f"Processing {event_type} file..."})
        
        # Clean up processed files dictionary
        PROCESSED_FILES = {path: timestamp 
                         for path, timestamp in PROCESSED_FILES.items()
                         if now - timestamp < IGNORE_INTERVAL}

        if file_path in PROCESSED_FILES:
            message_queue.put({'type': 'log', 
                             'content': f"Ignoring recently processed file: {os.path.basename(file_path)}"})
            return

        filename = os.path.basename(file_path)
        message_queue.put({'type': 'log', 
                          'content': f"{event_type} file: {filename}"})

        # Process file
        pattern_match = contains_patterns(filename, self.search_patterns)
        if pattern_match:
            number = extract_number(filename)
            if number:
                copy_to_clipboard(number)
                message_queue.put({'type': 'log', 
                                 'content': f"Copied number: {number}"})
            if event_type != "Deleted":
                if print_file(file_path):
                    message_queue.put({'type': 'increment_printed'})
                PROCESSED_FILES[file_path] = now
                message_queue.put({'type': 'increment_processed'})


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

def run_watcher():
    """Run the file watcher in a separate thread."""
    config_file = r'src/config_noGUI.ini'
    config = m.read_config(config_file)
    m.ensure_config_exists(config, config_file)
    config.read(config_file)

    watch_dir = config.get('settings', 'watch_dir', fallback='')
    search_patterns_str = config.get('settings', 'search_patterns', fallback='')
    search_patterns = [pattern.strip() 
                      for pattern in search_patterns_str.split(',') 
                      if pattern.strip()]

    message_queue.put({'type': 'status', 'content': "Initializing..."})
    message_queue.put({'type': 'log', 
                      'content': f"Watching directory: {watch_dir}"})
    
    try:
        validate_inputs(watch_dir, search_patterns)
        file_handler = FileHandler(search_patterns)
        
        message_queue.put({'type': 'status', 
                          'content': "Scanning existing files..."})
        scan_existing_files(watch_dir, file_handler)
        
        message_queue.put({'type': 'status', 
                          'content': "Watching for changes..."})
        watcher = Watcher(watch_dir, file_handler)
        watcher.run()
        
    except Exception as e:
        message_queue.put({'type': 'status', 'content': "Error occurred!"})
        message_queue.put({'type': 'log', 'content': f"Error: {str(e)}"})
        logger.error(f"An unexpected error occurred: {e}")


# --- Main Execution ---

def main():
    # Create and start GUI in the main thread
    status_window = StatusWindow()
    
    # Start the file watcher in a separate thread
    watcher_thread = threading.Thread(target=run_watcher)
    watcher_thread.daemon = True
    watcher_thread.start()
    
    # Run the main GUI loop
    status_window.root.mainloop()

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")