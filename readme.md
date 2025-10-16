# Secure File Sharing & Storage System

A college-level cryptography project implementing hybrid encryption with RSA-2048 and AES-256.

## Quick Start
```bash
# Setup
cd ~/CryptoFileShare
source venv/bin/activate
pip install cryptography

# Run
python3 main.py


"""


Test Scenario: Alice wants to send an encrypted file to Bob securely.
Create a test file first:
bash# Create a sample file to encrypt
echo "This is a top secret message from Alice to Bob!" > test_message.txt
echo "Meeting at 3 PM tomorrow." >> test_message.txt
echo "Project budget: $50,000" >> test_message.txt
Generate Alice's Keys:
bashpython3 main.py
```

When menu appears:
1. Select option **1** (Generate New Key Pair)
2. Enter user name: `alice`
3. Password-protect? Enter: `y`
4. Enter password: `alice123` (remember this!)
5. Confirm password: `alice123`

You should see:
```
[✓] RSA key pair generated successfully!
[✓] Private key saved to: keys/alice_private.pem
[✓] Public key saved to: keys/alice_public.pem
Generate Bob's Keys:

Press Enter to continue
Select option 1 again
Enter user name: bob
Password-protect? Enter: y
Enter password: bob456
Confirm password: bob456

Now verify your keys exist:
bashls -la keys/
```

You should see:
```
alice_private.pem
alice_public.pem
bob_private.pem
bob_public.pem
```

---

### Step 10: Alice Encrypts File for Bob

**Scenario:** Alice encrypts `test_message.txt` so only Bob can read it.

1. From main menu, select option **2** (Encrypt a File)
2. Enter path to file: `test_message.txt`
3. You'll see available public keys - select Bob's key (enter `2`)
4. Enter your private key path: `keys/alice_private.pem`
5. Is it password-protected? `y`
6. Enter password: `alice123`

**What's happening behind the scenes:**
```
Step 1: Reading test_message.txt
Step 2: Generating random AES-256 key
Step 3: Encrypting file with AES (fast symmetric encryption)
Step 4: Encrypting AES key with Bob's RSA public key
Step 5: Alice signs everything with her private key
Step 6: Packaging: encrypted file + encrypted key + signature
```

You should see:
```
[✓] File encrypted! Size: X bytes → Y bytes
[✓] AES key encrypted!
[✓] Signature created!
[✓] ENCRYPTION COMPLETE!
[✓] Encrypted package saved to: encrypted_files/test_message.txt.encrypted
Verify the encrypted file:
bashls -la encrypted_files/
```

---

### Step 11: Bob Decrypts the File

**Scenario:** Bob receives the encrypted file and decrypts it.

1. Press Enter to continue
2. Select option **3** (Decrypt a File)
3. Enter path to encrypted file: `encrypted_files/test_message.txt.encrypted`
4. Enter your private key path: `keys/bob_private.pem`
5. Is it password-protected? `y`
6. Enter password: `bob456`
7. Enter sender's public key: `keys/alice_public.pem`

**What's happening:**
```
Step 1: Verifying Alice's signature (proves it's from Alice)
Step 2: Bob decrypts AES key using his RSA private key
Step 3: Decrypting file using AES key
Step 4: Verifying file integrity with SHA-256 hash
```

You should see:
```
[*] Verifying digital signature...
[✓] Signature verified! Data is authentic.
[*] Decrypting AES key with RSA private key...
[✓] AES key decrypted!
[*] Decrypting file with AES...
[✓] File decrypted! Size: X bytes
[*] Verifying file integrity...
[✓] File integrity verified! Hash matches.
[✓] DECRYPTION COMPLETE!
Verify the decrypted file:
bashcat decrypted_files/test_message.txt
You should see the original message!

Step 12: Test File Integrity (Hash Verification)
Let's verify both files have the same hash:

From menu, select option 4 (View File Hash)
Enter file path: test_message.txt
Note the SHA-256 hash
Press Enter, select option 4 again
Enter file path: decrypted_files/test_message.txt
The hash should be identical!

This proves the file wasn't tampered with during encryption/decryption.

""""

🔬 Advanced Testing Scenarios
Step 13: Test Security Features
Test 1: Wrong Recipient (Should Fail)
bashpython3 main.py

Encrypt a file for Bob (option 2)
Try to decrypt with Alice's private key (option 3)
Result: Should fail! Only Bob's private key works.

Test 2: Tampered File Detection
bash# Manually corrupt the encrypted file
echo "HACKED" >> encrypted_files/test_message.txt.encrypted
Now try to decrypt:
bashpython3 main.py
# Select option 3, try to decrypt
Result: Should fail! The signature won't verify.
Test 3: Test Large File
bash# Create a larger file (1MB)
dd if=/dev/urandom of=large_file.bin bs=1024 count=1024

# Encrypt it
python3 main.py
# Follow encryption steps for large_file.bin
Time how long it takes - you'll see AES is VERY fast even for large files!

📊 Understanding the Cryptography
Step 14: Let's Examine What Happened
Open an encrypted package:
bashcat encrypted_files/test_message.txt.encrypted
You'll see JSON containing:
json{
  "ciphertext": "base64_encoded_encrypted_data",
  "encrypted_aes_key": "base64_encoded_key",
  "nonce": "base64_encoded_iv",
  "tag": "base64_encoded_auth_tag",
  "signature": "base64_encoded_signature",
  "original_hash": "sha256_hash",
  "original_filename": "test_message.txt"
}
Cryptographic Components Explained:

ciphertext: Your file encrypted with AES-256-GCM

Fast symmetric encryption
256-bit key = 2^256 possible keys (practically unbreakable)


encrypted_aes_key: The AES key encrypted with RSA-2048

Only Bob's private key can decrypt this
This is the "hybrid" part!


nonce: Initialization Vector (IV) for AES-GCM

96 bits random data
Ensures same plaintext → different ciphertext each time


tag: Authentication tag from AES-GCM

128 bits
Detects ANY tampering with ciphertext


signature: Digital signature using RSA-PSS with SHA-256

Proves Alice created this package
Non-repudiation: Alice can't deny sending it


original_hash: SHA-256 of original file

Integrity verification
Even 1 bit change = completely different hash

