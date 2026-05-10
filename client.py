import socket
from crypto_helpers import *

def start_client(my_keyname: str, their_keyname: str, message: str):
    public_key = load_rsa_public_key(their_keyname)

    aes_key_bytes, nonce, ciphertext = generate_key_and_encrypt(message)
    
    encrypted_aes_key_bytes = encrypt_with_rsa_public(public_key, aes_key_bytes)

    payload: bytes = generate_formatted_encrypted_message(encrypted_aes_key_bytes, nonce, ciphertext)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 9999))
        s.sendall(payload)
