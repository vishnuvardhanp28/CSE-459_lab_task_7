from tinyec import registry
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def generate_key_pair(curve):
    """Generate ECC private and public key pair."""
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g
    return private_key, public_key

def derive_shared_secret(private_key, public_key):
    """Derive shared secret from private and public key."""
    return private_key * public_key

def encrypt_message(message, shared_secret):
    """Encrypt message using AES with key derived from shared secret."""
    try:
        # Derive AES key from shared secret (truncate to 16 bytes for AES-128)
        secret_bytes = str(shared_secret.x).encode()
        key = hashlib.sha256(secret_bytes).digest()[:16]
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Encrypt
        message_bytes = message.encode()
        padded_message = pad(message_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        
        return iv + ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(ciphertext, shared_secret):
    """Decrypt message using AES with key derived from shared secret."""
    try:
        # Derive AES key from shared secret
        secret_bytes = str(shared_secret.x).encode()
        key = hashlib.sha256(secret_bytes).digest()[:16]
        
        # Extract IV and ciphertext
        iv = ciphertext[:16]
        encrypted_message = ciphertext[16:]
        
        # Create AES cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt
        padded_message = cipher.decrypt(encrypted_message)
        message = unpad(padded_message, AES.block_size)
        
        return message.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def ecc_encrypt_decrypt(curve_name, message):
    """Perform encryption and decryption with given curve."""
    print(f"\nUsing curve: {curve_name}")
    try:
        curve = registry.get_curve(curve_name)
        
        # Generate key pairs
        priv_key1, pub_key1 = generate_key_pair(curve)
        priv_key2, pub_key2 = generate_key_pair(curve)
        
        # Derive shared secrets
        shared_secret1 = derive_shared_secret(priv_key1, pub_key2)
        shared_secret2 = derive_shared_secret(priv_key2, pub_key1)
        
        # Encrypt
        ciphertext = encrypt_message(message, shared_secret1)
        if ciphertext is None:
            return
        
        print(f"Original message: {message}")
        print(f"Ciphertext (hex): {ciphertext.hex()}")
        
        # Decrypt
        decrypted_message = decrypt_message(ciphertext, shared_secret2)
        if decrypted_message is None:
            return
        
        print(f"Decrypted message: {decrypted_message}")
    except Exception as e:
        print(f"Error with curve {curve_name}: {e}")

# Test with two different curves
message = "Hell0 SRM AP"
curve1 = "secp256r1"      # NIST P-256
curve2 = "brainpoolP256r1" # Brainpool P-256

print("Performing ECC Encryption/Decryption...")
ecc_encrypt_decrypt(curve1, message)
ecc_encrypt_decrypt(curve2, message)