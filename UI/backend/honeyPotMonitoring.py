import csv
import time
import hashlib
import os
from PIL import Image
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from win10toast import ToastNotifier
import win32gui
import win32con
import time
import sys

# Function to calculate the hash of an image
def calculate_hash(image_path):
    with open(image_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

# Function to check if image is modified
def is_image_modified(image_path, last_hash):
    current_hash = calculate_hash(image_path)
    return current_hash != last_hash

# Event handler for file system events
class ImageChangeHandler(FileSystemEventHandler):
    def __init__(self, image_paths, last_hashes):
        self.image_paths = image_paths
        self.last_hashes = last_hashes

    def on_modified(self, event):
        for image_path, last_hash in zip(self.image_paths, self.last_hashes):
            if event.src_path == image_path:
                if is_image_modified(image_path, last_hash):
                    sys.stderr.write("600 Alert\n")
                    time.sleep(3)
                    sys.stderr.write(f"Image {image_path} has been modified!\n")
                    #toaster = ToastNotifier()
                    #toaster.show_toast("Image Modification Detected", "Image has been modified!")
                    # Notify user here (e.g., send email, display notification, etc.)
                self.last_hashes[self.image_paths.index(image_path)] = calculate_hash(image_path)

class FlashWindow:
    def __init__(self, title):
        self.title = title
        self.hwnd = None

    def flash(self):
        self.hwnd = win32gui.FindWindow(None, self.title)
        if self.hwnd:
            for _ in range(5):  # Flash for 5 times
                win32gui.FlashWindow(self.hwnd, True)
                time.sleep(0.5)

# Main function to monitor images for changes
def monitor_images(image_paths):
    last_hashes = [calculate_hash(image_path) for image_path in image_paths]
    event_handler = ImageChangeHandler(image_paths, last_hashes)
    observer = Observer()
    for image_path in image_paths:
        observer.schedule(event_handler, os.path.dirname(image_path), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Function to read CSV file and monitor images
def monitor_images_from_csv(csv_file):
    try:
        with open(csv_file, 'r') as file:
            reader = csv.reader(file)
            image_paths = []
            for row in reader:
                if len(row) == 3:
                    file_name, extension, file_path = row
                    if file_name.endswith("_hpot") and extension.lower() == ".jpg":
                        image_path = os.path.join(file_path, file_name + extension)
                        image_paths.append(image_path)
        if image_paths:
            monitor_images(image_paths)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    sys.stderr.write("Honeypot monitoring started\n")
    csv_file = "file_info.csv"
    monitor_images_from_csv(csv_file)

