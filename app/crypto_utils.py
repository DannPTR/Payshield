from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os

# Path untuk menyimpan kunci
KEYS_DIR = 'keys'
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, 'private_key.pem')
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, 'public_key.pem')

def generate_or_load_keys():
    """Generate new RSA keys if they don't exist, or load existing keys"""
    # Buat direktori keys jika belum ada
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    
    # Jika kunci belum ada, buat kunci baru
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Simpan private key
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Simpan public key
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        # Load kunci yang sudah ada
        with open(PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    
    return private_key, public_key

def encrypt_data(public_key, data):
    """Enkripsi data menggunakan public key"""
    return base64.b64encode(
        public_key.encrypt(
            str(data).encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    ).decode()

def decrypt_data(private_key, encrypted_data):
    """Dekripsi data menggunakan private key"""
    try:
        return private_key.decrypt(
            base64.b64decode(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def hash_data(data):
    """Generate hash dari data"""
    return hashlib.sha256(str(data).encode()).hexdigest()