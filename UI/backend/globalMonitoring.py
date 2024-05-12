import os
import random
import time
import logging
import sys  # Import sys module
from PIL import Image, ImageDraw
import csv

# Setup logging
logging.basicConfig(filename='monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def monitor_directory_changes(root_dir, honeypot_path):
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
            sys.stderr.write(f"New items detected: {new_items}\n")
            for item in new_items:
                if os.path.isdir(os.path.join(root_dir, item)):
                    create_symlink(os.path.join(root_dir, item), honeypot_path)

        # Check for deleted files/directories
        deleted_items = compare_directory_structure(current_structure, initial_structure)
        if deleted_items:
            logging.info(f"Deleted items detected: {deleted_items}")
            sys.stderr.write(f"Deleted items detected: {deleted_items}\n")
        
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

def create_symlink(new_directory, target_file):
    """Create a symbolic link in the specified directory pointing to the target file."""
    symlink_name = os.path.join(new_directory, os.path.basename(target_file))
    print(target_file)
    os.symlink(target_file, symlink_name)

def create_honeypot(directory):
    """Create hidden honey pot files in the specified directory."""
    filename = generate_random_filename()
    filenameWithExt = filename + '.jpg'
    filepath = os.path.join(directory, filenameWithExt)
    create_image(filepath)
    add_file_info_to_csv(filename, '.jpg', directory)
    return filepath

def generate_random_filename():
    """Generate a random filename with the specified extension."""
    adjectives = ['funny', 'silly', 'wacky', 'goofy', 'crazy', 'quirky', 'whimsical']
    nouns = ['banana', 'kangaroo', 'unicorn', 'penguin', 'squirrel', 'pickle', 'robot']
    adjective = random.choice(adjectives)
    noun = random.choice(nouns)
    return f"{adjective}_{noun}_hpot"

def create_image(file_path):
    """Create an image with text."""
    width, height = 200, 200
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    draw.text((10, 10), "This is a secure image", fill="black")
    image.save(file_path)
    
def add_file_info_to_csv(file_name, extension, directory):
    csv_file = "file_info.csv"
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([file_name, extension, directory])

if _name_ == "_main_":
    # Check if the log file exists and delete it
    try:
        if os.path.exists('monitor.log'):
            os.remove('monitor.log')
    except:
        pass

    # Create the necessary directory for honeypot if it doesn't exist
    honeypot_directory = os.path.abspath('./windos32/system32')  # Get absolute path of the honeypot directory
    os.makedirs(honeypot_directory, exist_ok=True)

    # Create a honeypot file in the predefined directory
    honeypot_path = create_honeypot(honeypot_directory)

    # Start global monitoring
    sys.stderr.write(f"{_file_}: Global Monitoring Started\n")
    monitor_directory_changes(os.getcwd(), honeypot_path)