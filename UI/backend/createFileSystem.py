import os

# Define the base path
base_path = os.path.dirname(os.path.abspath(__file__)) + "/FileSystem"

# Define the directory structure to mimic a simple Ubuntu file system
directories = [
    'bin',
    'boot',
    'dev',
    'etc',
    'home',
    'lib',
    'media',
    'mnt',
    'opt',
    'proc',
    'root',
    'sbin',
    'srv',
    'sys',
    'tmp',
    'usr/bin',
    'usr/include',
    'usr/lib',
    'usr/sbin',
    'usr/share',
    'var/cache',
    'var/lib',
    'var/log',
    'var/mail',
    'var/spool',
    'var/tmp',
]

# Create the directories
for dir in directories:
    full_path = os.path.join(base_path, dir)
    os.makedirs(full_path, exist_ok=True)

print(f"File structure created under '{base_path}'")