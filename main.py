"""
Secure File Sharing & Storage System
Main User Interface

This provides a command-line interface for:
- Generating key pairs
- Encrypting files
- Decrypting files
- Managing keys
"""

import os
import sys
from crypto_system import HybridCryptoSystem
from getpass import getpass


def print_banner():
    """Display application banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║      SECURE FILE SHARING & STORAGE SYSTEM                ║
    ║      Hybrid Encryption (RSA-2048 + AES-256)              ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu():
    """Display main menu."""
    menu = """
    ┌──────────────────────────────────────────────────────────┐
    │  MAIN MENU                                               │
    ├──────────────────────────────────────────────────────────┤
    │  1. Generate New Key Pair                                │
    │  2. Encrypt a File                                       │
    │  3. Decrypt a File                                       │
    │  4. View File Hash (SHA-256)                             │
    │  5. Exit                                                 │
    └──────────────────────────────────────────────────────────┘
    """
    print(menu)


def generate_keypair():
    """Generate RSA key pair for a user."""
    print("\n" + "="*60)
    print("KEY PAIR GENERATION")
    print("="*60)
    
    user_name = input("Enter user name (e.g., alice, bob): ").strip()
    
    if not user_name:
        print("[✗] Invalid user name!")
        return
    
    # Ask for password protection
    protect = input("Password-protect private key? (y/n): ").strip().lower()
    password = None
    
    if protect == 'y':
        password = getpass("Enter password for private key: ")
        confirm = getpass("Confirm password: ")
        
        if password != confirm:
            print("[✗] Passwords don't match!")
            return
    
    # Generate keys
    crypto = HybridCryptoSystem()
    crypto.generate_rsa_keypair(key_size=2048)
    
    # Save keys
    private_key_path = f"keys/{user_name}_private.pem"
    public_key_path = f"keys/{user_name}_public.pem"
    
    crypto.save_keys(private_key_path, public_key_path, password)
    
    print(f"\n[✓] Keys generated successfully!")
    print(f"[✓] Share your public key: {public_key_path}")
    print(f"[✓] Keep your private key safe: {private_key_path}")
    print("="*60 + "\n")


def encrypt_file():
    """Encrypt a file for a recipient."""
    print("\n" + "="*60)
    print("FILE ENCRYPTION")
    print("="*60)
    
    # Get file to encrypt
    file_path = input("Enter path to file to encrypt: ").strip()
    
    if not os.path.exists(file_path):
        print(f"[✗] File not found: {file_path}")
        return
    
    # List available public keys
    print("\nAvailable public keys in 'keys/' directory:")
    public_keys = [f for f in os.listdir('keys') if f.endswith('_public.pem')]
    
    if not public_keys:
        print("[✗] No public keys found! Generate keys first.")
        return
    
    for i, key in enumerate(public_keys, 1):
        print(f"  {i}. {key}")
    
    # Select recipient
    try:
        choice = int(input("\nSelect recipient's public key (number): "))
        recipient_key = f"keys/{public_keys[choice - 1]}"
    except (ValueError, IndexError):
        print("[✗] Invalid choice!")
        return
    
    # Get sender's private key for signing
    print("\nYou need your private key to sign the file.")
    sender_private = input("Enter your private key path: ").strip()
    
    if not os.path.exists(sender_private):
        print(f"[✗] Private key not found: {sender_private}")
        return
    
    # Load sender's private key
    password = None
    if input("Is your private key password-protected? (y/n): ").strip().lower() == 'y':
        password = getpass("Enter private key password: ")
    
    crypto = HybridCryptoSystem()
    
    try:
        crypto.load_keys(private_key_path=sender_private, password=password)
    except Exception as e:
        print(f"[✗] Failed to load private key: {e}")
        return
    
    # Output path
    filename = os.path.basename(file_path)
    output_path = f"encrypted_files/{filename}.encrypted"
    
    # Encrypt
    try:
        crypto.encrypt_and_package(file_path, recipient_key, output_path)
        print(f"[✓] File encrypted and saved to: {output_path}")
    except Exception as e:
        print(f"[✗] Encryption failed: {e}")


def decrypt_file():
    """Decrypt a file."""
    print("\n" + "="*60)
    print("FILE DECRYPTION")
    print("="*60)
    
    # Get encrypted file
    encrypted_file = input("Enter path to encrypted file: ").strip()
    
    if not os.path.exists(encrypted_file):
        print(f"[✗] File not found: {encrypted_file}")
        return
    
    # Get recipient's private key
    private_key = input("Enter your private key path: ").strip()
    
    if not os.path.exists(private_key):
        print(f"[✗] Private key not found: {private_key}")
        return
    
    # Get sender's public key for verification
    print("\nYou need sender's public key to verify signature.")
    sender_public = input("Enter sender's public key path: ").strip()
    
    if not os.path.exists(sender_public):
        print(f"[✗] Public key not found: {sender_public}")
        return
    
    # Load private key
    password = None
    if input("Is your private key password-protected? (y/n): ").strip().lower() == 'y':
        password = getpass("Enter private key password: ")
    
    crypto = HybridCryptoSystem()
    
    try:
        crypto.load_keys(private_key_path=private_key, password=password)
    except Exception as e:
        print(f"[✗] Failed to load private key: {e}")
        return
    
    # Decrypt
    try:
        success = crypto.decrypt_and_verify(
            encrypted_file,
            'decrypted_files',
            sender_public
        )
        
        if success:
            print("[✓] File decrypted successfully!")
        else:
            print("[✗] Decryption completed but verification failed!")
    except Exception as e:
        print(f"[✗] Decryption failed: {e}")


def view_file_hash():
    """Calculate and display file hash."""
    print("\n" + "="*60)
    print("FILE HASH (SHA-256)")
    print("="*60)
    
    file_path = input("Enter file path: ").strip()
    
    if not os.path.exists(file_path):
        print(f"[✗] File not found: {file_path}")
        return
    
    crypto = HybridCryptoSystem()
    file_hash = crypto.hash_file(file_path)
    
    print(f"\nFile: {file_path}")
    print(f"SHA-256: {file_hash}")
    print("="*60 + "\n")


def main():
    """Main application loop."""
    print_banner()
    
    # Ensure directories exist
    os.makedirs('keys', exist_ok=True)
    os.makedirs('encrypted_files', exist_ok=True)
    os.makedirs('decrypted_files', exist_ok=True)
    
    while True:
        print_menu()
        choice = input("Enter your choice (1-5): ").strip()
        
        if choice == '1':
            generate_keypair()
        elif choice == '2':
            encrypt_file()
        elif choice == '3':
            decrypt_file()
        elif choice == '4':
            view_file_hash()
        elif choice == '5':
            print("\n[✓] Thank you for using Secure File Sharing System!")
            print("[✓] Stay secure! 🔒\n")
            sys.exit(0)
        else:
            print("\n[✗] Invalid choice! Please select 1-5.\n")
        
        input("\nPress Enter to continue...")
        print("\n" * 2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[✓] Program terminated by user. Goodbye! 🔒\n")
        sys.exit(0)