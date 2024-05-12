from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad
from PIL import Image
import os

# Function to encrypt image
def encrypt_image(input_path, password):
    # Load the image
    image = Image.open(input_path)
    # Convert the image to bytes
    image_bytes = image.tobytes()

    # Generate a random salt
    salt = get_random_bytes(16)

    # Derive a key from the password and salt
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)

    # Generate initialization vector
    iv = get_random_bytes(16)

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the image bytes
    padded_image_bytes = pad(image_bytes, AES.block_size)

    # Encrypt the image bytes
    encrypted_image_bytes = cipher.encrypt(padded_image_bytes)

    # Save the encrypted image to the same file
    with open(input_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(encrypted_image_bytes)

    print(f"{input_path} encrypted successfully!")

# Function to encrypt images in a directory and its subdirectories
def encrypt_images_in_directory(directory_path, password):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.lower().endswith("_hpot.jpg"):
                file_path = os.path.join(root, file)
                encrypt_image(file_path, password)

# Example usage
if __name__ == "__main__":
    input_folder_path = "/home/cheithanya/Desktop/Finalyearproject/UI/backend/windos32/system32"  # Replace "folder_path" with the path to your folder
    password = "YourPasswordHere"  # Replace with your password

    encrypt_images_in_directory(input_folder_path, password)