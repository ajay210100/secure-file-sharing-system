"""
Secure File Sharing & Storage System with Hybrid Encryption
Core Cryptography Module

This module implements:
1. RSA-2048 for asymmetric encryption (key exchange)
2. AES-256-GCM for symmetric encryption (file encryption)
3. SHA-256 for hashing and integrity
4. Digital signatures for authenticity verification
"""


import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64


class HybridCryptoSystem:
    """
    Implements hybrid encryption combining RSA and AES.
    
    Architecture:
    - RSA (Asymmetric): Used for encrypting/decrypting the AES key
    - AES-GCM (Symmetric): Used for encrypting/decrypting actual file data
    - SHA-256: Used for hashing and integrity verification
    """
    
    def __init__(self):
        self.backend = default_backend()
        self.private_key = None
        self.public_key = None
        
    # ==================== KEY GENERATION ====================
    
    def generate_rsa_keypair(self, key_size=2048):
        """
        Generate RSA key pair for asymmetric encryption.
        
        Args:
            key_size (int): RSA key size (2048 or 4096 bits)
            
        Returns:
            tuple: (private_key, public_key)
            
        Security Note:
            - 2048 bits is currently considered secure
            - 4096 bits provides extra security margin but slower
        """
        print(f"[*] Generating RSA-{key_size} key pair...")
        
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard exponent (e)
            key_size=key_size,
            backend=self.backend
        )
        
        # Derive public key from private key
        self.public_key = self.private_key.public_key()
        
        print("[✓] RSA key pair generated successfully!")
        return self.private_key, self.public_key
    
    def save_keys(self, private_key_path, public_key_path, password=None):
        """
        Save RSA keys to PEM format files.
        
        Args:
            private_key_path (str): Path to save private key
            public_key_path (str): Path to save public key
            password (str): Optional password to encrypt private key
            
        Security Note:
            - Private key can be password-protected (recommended)
            - Public key is stored in plaintext (it's meant to be public)
        """
        print("[*] Saving keys to disk...")
        
        # Prepare encryption algorithm for private key
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password.encode()
            )
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        # Serialize and save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Serialize and save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        print(f"[✓] Private key saved to: {private_key_path}")
        print(f"[✓] Public key saved to: {public_key_path}")
    
    def load_keys(self, private_key_path=None, public_key_path=None, password=None):
        """
        Load RSA keys from PEM files.
        
        Args:
            private_key_path (str): Path to private key file
            public_key_path (str): Path to public key file
            password (str): Password if private key is encrypted
        """
        if private_key_path:
            with open(private_key_path, 'rb') as f:
                key_data = f.read()
            
            pwd = password.encode() if password else None
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=pwd,
                backend=self.backend
            )
            print(f"[✓] Private key loaded from: {private_key_path}")
        
        if public_key_path:
            with open(public_key_path, 'rb') as f:
                key_data = f.read()
            
            self.public_key = serialization.load_pem_public_key(
                key_data,
                backend=self.backend
            )
            print(f"[✓] Public key loaded from: {public_key_path}")
    
    # ==================== SYMMETRIC ENCRYPTION (AES) ====================
    
    def generate_aes_key(self):
        """
        Generate a random 256-bit AES key.
        
        Returns:
            bytes: 32-byte (256-bit) random key
            
        Security Note:
            - Uses OS-level cryptographically secure random generator
            - Each file gets a unique AES key (best practice)
        """
        return os.urandom(32)  # 256 bits = 32 bytes
    
    def encrypt_file_aes(self, file_path):
        """
        Encrypt a file using AES-256-GCM.
        
        Args:
            file_path (str): Path to file to encrypt
            
        Returns:
            tuple: (encrypted_data, aes_key, nonce, tag)
            
        How AES-GCM works:
            1. Generate random key and nonce (IV)
            2. Encrypt data in chunks
            3. Generate authentication tag (prevents tampering)
        """
        print(f"[*] Encrypting file: {file_path}")
        
        # Read the file
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Generate AES key and nonce (IV)
        aes_key = self.generate_aes_key()
        nonce = os.urandom(12)  # GCM standard: 96 bits
        
        # Create AES-GCM cipher
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        
        # Encrypt the file
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Get authentication tag (for integrity verification)
        tag = encryptor.tag
        
        print(f"[✓] File encrypted! Size: {len(plaintext)} bytes → {len(ciphertext)} bytes")
        
        return ciphertext, aes_key, nonce, tag
    
    def decrypt_file_aes(self, ciphertext, aes_key, nonce, tag):
        """
        Decrypt file using AES-256-GCM.
        
        Args:
            ciphertext (bytes): Encrypted data
            aes_key (bytes): AES key
            nonce (bytes): Initialization vector
            tag (bytes): Authentication tag
            
        Returns:
            bytes: Decrypted plaintext
            
        Security Note:
            - Tag verification happens automatically
            - Decryption fails if data has been tampered with
        """
        print("[*] Decrypting file with AES...")
        
        # Create AES-GCM cipher
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        print(f"[✓] File decrypted! Size: {len(plaintext)} bytes")
        
        return plaintext
    
    # ==================== ASYMMETRIC ENCRYPTION (RSA) ====================
    
    def encrypt_aes_key_rsa(self, aes_key, recipient_public_key):
        """
        Encrypt AES key using RSA public key.
        
        Args:
            aes_key (bytes): AES key to encrypt
            recipient_public_key: RSA public key
            
        Returns:
            bytes: Encrypted AES key
            
        Why RSA for key exchange?
            - Only recipient with private key can decrypt
            - Enables secure key sharing over insecure channels
        """
        encrypted_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted_key
    
    def decrypt_aes_key_rsa(self, encrypted_key):
        """
        Decrypt AES key using RSA private key.
        
        Args:
            encrypted_key (bytes): Encrypted AES key
            
        Returns:
            bytes: Decrypted AES key
        """
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return aes_key
    
    # ==================== DIGITAL SIGNATURES ====================
    
    def sign_data(self, data):
        """
        Create digital signature using private key.
        
        Args:
            data (bytes): Data to sign
            
        Returns:
            bytes: Digital signature
            
        Purpose:
            - Proves data came from private key holder
            - Detects any modifications to data
        """
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify_signature(self, data, signature, signer_public_key):
        """
        Verify digital signature using public key.
        
        Args:
            data (bytes): Original data
            signature (bytes): Signature to verify
            signer_public_key: Signer's public key
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            signer_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    # ==================== FILE HASHING ====================
    
    def hash_file(self, file_path):
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path (str): Path to file
            
        Returns:
            str: Hexadecimal hash string
            
        Use case:
            - Verify file integrity
            - Detect corruption or tampering
        """
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        
        with open(file_path, 'rb') as f:
            # Read in chunks for memory efficiency
            while chunk := f.read(8192):
                digest.update(chunk)
        
        return digest.finalize().hex()
    
    # ==================== COMPLETE ENCRYPTION WORKFLOW ====================
    
    def encrypt_and_package(self, file_path, recipient_public_key_path, output_path):
        """
        Complete encryption workflow:
        1. Encrypt file with AES
        2. Encrypt AES key with recipient's RSA public key
        3. Sign the encrypted data
        4. Package everything together
        
        Args:
            file_path (str): File to encrypt
            recipient_public_key_path (str): Recipient's public key
            output_path (str): Where to save encrypted package
        """
        print("\n" + "="*60)
        print("STARTING HYBRID ENCRYPTION PROCESS")
        print("="*60)
        
        # Load recipient's public key
        with open(recipient_public_key_path, 'rb') as f:
            recipient_public_key = serialization.load_pem_public_key(
                f.read(),
                backend=self.backend
            )
        
        # Step 1: Encrypt file with AES
        ciphertext, aes_key, nonce, tag = self.encrypt_file_aes(file_path)
        
        # Step 2: Encrypt AES key with RSA
        print("[*] Encrypting AES key with RSA...")
        encrypted_aes_key = self.encrypt_aes_key_rsa(aes_key, recipient_public_key)
        print("[✓] AES key encrypted!")
        
        # Step 3: Create digital signature
        print("[*] Creating digital signature...")
        signature = self.sign_data(ciphertext)
        print("[✓] Signature created!")
        
        # Step 4: Calculate original file hash
        original_hash = self.hash_file(file_path)
        
        # Step 5: Package everything
        package = {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'signature': base64.b64encode(signature).decode(),
            'original_hash': original_hash,
            'original_filename': os.path.basename(file_path)
        }
        
        # Save package
        with open(output_path, 'w') as f:
            json.dump(package, f, indent=2)
        
        print(f"\n[✓] ENCRYPTION COMPLETE!")
        print(f"[✓] Encrypted package saved to: {output_path}")
        print(f"[✓] Original file hash (SHA-256): {original_hash}")
        print("="*60 + "\n")
    
    def decrypt_and_verify(self, package_path, output_dir, sender_public_key_path):
        """
        Complete decryption workflow:
        1. Load encrypted package
        2. Decrypt AES key with private RSA key
        3. Verify digital signature
        4. Decrypt file with AES
        5. Verify file integrity with hash
        
        Args:
            package_path (str): Path to encrypted package
            output_dir (str): Where to save decrypted file
            sender_public_key_path (str): Sender's public key (for signature verification)
        """
        print("\n" + "="*60)
        print("STARTING HYBRID DECRYPTION PROCESS")
        print("="*60)
        
        # Load package
        with open(package_path, 'r') as f:
            package = json.load(f)
        
        # Decode from base64
        ciphertext = base64.b64decode(package['ciphertext'])
        encrypted_aes_key = base64.b64decode(package['encrypted_aes_key'])
        nonce = base64.b64decode(package['nonce'])
        tag = base64.b64decode(package['tag'])
        signature = base64.b64decode(package['signature'])
        original_hash = package['original_hash']
        original_filename = package['original_filename']
        
        # Step 1: Verify signature
        print("[*] Verifying digital signature...")
        with open(sender_public_key_path, 'rb') as f:
            sender_public_key = serialization.load_pem_public_key(
                f.read(),
                backend=self.backend
            )
        
        if self.verify_signature(ciphertext, signature, sender_public_key):
            print("[✓] Signature verified! Data is authentic.")
        else:
            print("[✗] SIGNATURE VERIFICATION FAILED! Data may be tampered!")
            return False
        
        # Step 2: Decrypt AES key with RSA
        print("[*] Decrypting AES key with RSA private key...")
        aes_key = self.decrypt_aes_key_rsa(encrypted_aes_key)
        print("[✓] AES key decrypted!")
        
        # Step 3: Decrypt file with AES
        plaintext = self.decrypt_file_aes(ciphertext, aes_key, nonce, tag)
        
        # Step 4: Save decrypted file
        output_path = os.path.join(output_dir, original_filename)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        # Step 5: Verify integrity
        print("[*] Verifying file integrity...")
        decrypted_hash = self.hash_file(output_path)
        
        if decrypted_hash == original_hash:
            print("[✓] File integrity verified! Hash matches.")
        else:
            print("[✗] Hash mismatch! File may be corrupted.")
            return False
        
        print(f"\n[✓] DECRYPTION COMPLETE!")
        print(f"[✓] Decrypted file saved to: {output_path}")
        print(f"[✓] File hash (SHA-256): {decrypted_hash}")
        print("="*60 + "\n")
        
        return True