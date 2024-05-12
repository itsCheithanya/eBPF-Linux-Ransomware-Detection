import os
import random
import string
import time
import ctypes
import logging
import csv
import sys  # Import sys module
from PIL import Image, ImageDraw

# Setup logging
logging.basicConfig(filename='monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def monitor_directory_changes(root_dir):
    """Monitor changes in the specified directory."""
    # Keep track of initial file and directory structure
    initial_structure = get_directory_structure(root_dir)
    
    # Monitor for changes
    while True:
        current_structure = get_directory_structure(root_dir)
        
        # Check for newly created files/directories
        new_items = compare_directory_structure(initial_structure, current_structure)
        if new_items:
            logging.info(f"New items detected: {new_items}")
            sys.stderr.write(f"New items detected: {new_items}\n")  # Use sys.stderr.write
            for item in new_items:
                if os.path.isdir(os.path.join(root_dir, item)):
                    create_honeypot(os.path.join(root_dir, item))

        # Check for deleted files/directories
        deleted_items = compare_directory_structure(current_structure, initial_structure)
        if deleted_items:
            logging.info(f"Deleted items detected: {deleted_items}")
            sys.stderr.write(f"Deleted items detected: {deleted_items}\n")  # Use sys.stderr.write
        
        # Update initial structure
        initial_structure = current_structure
        
        # Sleep for some time before checking again
        time.sleep(5)

def get_directory_structure(root_dir):
    """Get the directory structure as a dictionary."""
    dir_structure = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        relative_path = os.path.relpath(dirpath, root_dir)
        dir_structure[relative_path] = {
            'directories': dirnames,
            'files': filenames
        }
    return dir_structure

def compare_directory_structure(old_structure, new_structure):
    """Compare two directory structures and return the differences."""
    differences = []
    for path, data in new_structure.items():
        if path not in old_structure:
            differences.append(path)
        else:
            old_files = set(old_structure[path]['files'])
            new_files = set(data['files'])
            new_items = new_files - old_files
            if new_items:
                differences.extend([os.path.join(path, item) for item in new_items])
    return differences

def create_honeypot(directory):
    """Create hidden honey pot files in the specified directory."""
    # Create .jpg images only
    filename = generate_random_filename()
    filenameWithExt = filename + '.jpg'
    filepath = os.path.join(directory, filenameWithExt)
    create_image(filepath)
    add_file_info_to_csv(filename, '.jpg', directory)

def generate_random_filename():
    """Generate a random filename with the specified extension."""
    adjectives = ['funny', 'silly', 'wacky', 'goofy', 'crazy', 'quirky', 'whimsical']
    nouns = ['banana', 'kangaroo', 'unicorn', 'penguin', 'squirrel', 'pickle', 'robot']
    adjective = random.choice(adjectives)
    noun = random.choice(nouns)
    return f"{adjective}_{noun}_hpot"

def add_file_info_to_csv(file_name, extension, directory):
    csv_file = "file_info.csv"
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([file_name, extension, directory])

def remove_deleted_folders_from_csv(deleted_folders):
    csv_file = "file_info.csv"
    updated_rows = []
    base_dir = os.getcwd()
    sys.stderr.write("----------------------\n")  # Use sys.stderr.write
    for i in range(len(deleted_folders)):
        deleted_folders[i] = base_dir + '\\' + deleted_folders[i]
        sys.stderr.write(f"{deleted_folders[i]}\n")  # Use sys.stderr.write

    with open(csv_file, mode='r', newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[2] not in deleted_folders:
                updated_rows.append(row)

    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(updated_rows)

def create_image(file_path):
    """Create an image with text."""
    width, height = 200, 200
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    draw.text((10, 10), "This is a secure image", fill="black")
    image.save(file_path)

if __name__ == "__main__":
    # Check if the log file exists and delete it
    try:
        if os.path.exists('monitor.log'):
            os.remove('monitor.log')
    except:
        pass


    # Check if the CSV file exists and delete it
    try:
        if os.path.exists('file_info.csv'):
            os.remove('file_info.csv')
    except:
        pass

    # Start global monitoring
    sys.stderr.write(f"{__file__}: Global Monitoring Started\n")
    monitor_directory_changes(os.getcwd())
