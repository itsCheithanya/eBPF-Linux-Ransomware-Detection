"""
This code accomplishes the following 
1) Reads file_info.csv file every 10 seconds
2) it will find all the images that ends with "_hpot" and has extension ".jpg" from the csv file and records its path
3) calculates the hash of the above images
4) keeps monitoring the above images for any changes
5) notifies when the images are encrypted
"""


#pip install notify2
import notify2
import csv
import time
import hashlib
import os
from PIL import Image
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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
    def _init_(self, image_paths, last_hashes):
        self.image_paths = image_paths
        self.last_hashes = last_hashes

    def on_modified(self, event):
        for image_path, last_hash in zip(self.image_paths, self.last_hashes):
            if event.src_path == image_path:
                if is_image_modified(image_path, last_hash):
                    print(f"Image {image_path} has been modified!")
                    notify2.init("Image Modification Detected")
                    n = notify2.Notification(f"Image {image_path} has been modified!")
                    n.show()
                    # Notify user here (e.g., send email, display notification, etc.)
                self.last_hashes[self.image_paths.index(image_path)] = calculate_hash(image_path)

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
    except Exception as e:
        print("Error:", e)

if _name_ == "_main_":
    csv_file = "file_info.csv"
    monitor_images_from_csv(csv_file)



#old versions of the code
# import os
# import logging
# import time
# from multiprocessing import Process
# from openpyxl import load_workbook

# # Setup logging
# logging.basicConfig(filename='file_monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# def fork_child_process():
#     """Fork a new child process and print its ID."""
#     child_process = Process(target=monitor_tracked_files)
#     child_process.start()
#     print(f"Child process ID: {child_process.pid}")
#     logging.info(f"Child process ID: {child_process.pid}")

# def monitor_tracked_files():
#     """Monitor the tracked files for modifications."""
#     tracked_files = load_tracked_files()
#     logging.info("Started monitoring tracked files.")
#     print("Started monitoring tracked files.")

#     while True:
#         for filename, filepath in tracked_files.items():
#             if os.path.exists(filepath):
#                 # Check for modifications
#                 if has_file_changed(filepath):
#                     logging.warning(f"File '{filename}' at '{filepath}' has been modified!")
#                     print(f"File '{filename}' at '{filepath}' has been modified!")
#             else:
#                 logging.warning(f"File '{filename}' at '{filepath}' no longer exists!")
#                 print(f"File '{filename}' at '{filepath}' no longer exists!")
#         time.sleep(5)

# def load_tracked_files():
#     """Load tracked file details from 'file_info.xlsx'."""
#     tracked_files = {}
#     if os.path.exists('file_info.xlsx'):
#         wb = load_workbook('file_info.xlsx')
#         ws = wb.active
#         for row in ws.iter_rows(min_row=2, values_only=True):
#             filename, filepath = row[0], row[2]
#             tracked_files[filename] = filepath
#     return tracked_files

# def has_file_changed(filepath):
#     """Check if the file has been modified."""
#     try:
#         with open(filepath, 'r') as f:
#             content = f.read()
#         return False
#     except Exception:
#         return True

# if _name_ == "_main_":
#     # Fork a child process
#     fork_child_process()



# import csv
# import time
# import hashlib
# import os
# from PIL import Image
# from watchdog.observers import Observer
# from watchdog.events import FileSystemEventHandler

# # Function to calculate the hash of an image
# def calculate_hash(image_path):
#     with open(image_path, 'rb') as f:
#         return hashlib.sha256(f.read()).hexdigest()

# # Function to check if image is modified
# def is_image_modified(image_path, last_hash):
#     current_hash = calculate_hash(image_path)
#     return current_hash != last_hash

# # Event handler for file system events
# class ImageChangeHandler(FileSystemEventHandler):
#     def _init_(self, image_paths, last_hashes):
#         self.image_paths = image_paths
#         self.last_hashes = last_hashes

#     def on_modified(self, event):
#         for image_path, last_hash in zip(self.image_paths, self.last_hashes):
#             if event.src_path == image_path:
#                 if is_image_modified(image_path, last_hash):
#                     print(f"Image {image_path} has been modified!")
#                     # Notify user here (e.g., send email, display notification, etc.)
#                 self.last_hashes[self.image_paths.index(image_path)] = calculate_hash(image_path)

# # Main function to monitor images for changes
# def monitor_images(image_paths):
#     last_hashes = [calculate_hash(image_path) for image_path in image_paths]
#     event_handler = ImageChangeHandler(image_paths, last_hashes)
#     observer = Observer()
#     for image_path in image_paths:
#         observer.schedule(event_handler, os.path.dirname(image_path), recursive=False)
#     observer.start()
#     try:
#         while True:
#             time.sleep(1)
#     except KeyboardInterrupt:
#         observer.stop()
#     observer.join()

# # Function to read CSV file and monitor images
# def monitor_images_from_csv(csv_file):
#     try:
#         with open(csv_file, 'r') as file:
#             reader = csv.reader(file)
#             image_paths = []
#             for row in reader:
#                 if len(row) == 3:
#                     file_name, extension, file_path = row
#                     if file_name.endswith("_hpot") and extension.lower() == ".jpg":
#                         image_path = os.path.join(file_path, file_name + extension)
#                         image_paths.append(image_path)
#         if image_paths:
#             monitor_images(image_paths)
#     except KeyboardInterrupt:
#         pass
#     except Exception as e:
#         print("Error:", e)

# if _name_ == "_main_":
#     csv_file = "file_info.csv"
#     monitor_images_from_csv(csv_file)