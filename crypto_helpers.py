import os
import sys
import struct
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

"""
    Unpack message payload
"""
def get_key_and_size_formatted_encrypted_message_header(message: bytes, private_key: rsa.RSAPrivateKey) -> tuple[AESGCM, bytes, int]:
    assert(len(message) == 528)

    encrypted_aes_key_bytes, nonce, size_bytes = struct.unpack('>512s12sI', message)

    aes_key_bytes = (
        private_key.decrypt(
            #Right here we are decypting the shared AES Key using Alice's private key
            encrypted_aes_key_bytes,

            #padding was used in the encryption process because encrypting too little information with RSA can cause issues
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    )

    return AESGCM(aes_key_bytes), nonce, size_bytes

"""
    Generate formatted encrypted message payload
"""
def generate_formatted_encrypted_message(rsa_encrypted_aes_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    header = struct.pack('>512s12sI', rsa_encrypted_aes_key, nonce, len(ciphertext))
    full_packet = header + ciphertext

    return full_packet

"""
    Encrypt using the provided RSA Public Key
"""
def encrypt_with_rsa_public(key: crypto.PKey, message_bytes: bytes) -> bytes:
    rsa_key: RSAPublicKey = key.to_cryptography_key()
    return (
        rsa_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    )

"""
Decrypt AES GCM Message
"""
def decrypt_aes_message(aes_key: AESGCM, nonce: bytes, ciphertext: bytes) -> bytes:
    return (
        aes_key.decrypt(
            nonce,
            ciphertext,
            None
        )
    )

"""
Encrypt A message Using AES GCM using a New Key

returns (key: bytes, ciphertext: bytes)
"""
def generate_key_and_encrypt(message: str) -> tuple[bytes, bytes, bytes]:
    key_bytes = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key_bytes)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)

    return key_bytes, nonce, ciphertext

"""
    Generate a new random AES key (really just random bits)
"""
def generate_aes_key():
    return os.urandom(32)

"""
    Generate RSA Private Key and store in the file named <keyname>.pem and <keyname>.pub (for public key)
"""
def generate_and_save_rsa_key(keyname: str):
    private_key = crypto.PKey()

    private_key.generate_key(crypto.TYPE_RSA, 4096)
    priv_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
    pub_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, private_key)

    with open(keyname + ".pem", "wb") as f:
        f.write(priv_key_pem)

    with open(keyname + ".pub", "wb") as f:
        f.write(pub_key_pem)

"""
    Load RSA Key-Pair from PEM file
"""
def load_rsa_private_key(keyname: str) -> crypto.PKey:
    with open(keyname + ".pem", "rb") as f:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

"""
    Load RSA Public Key from file
"""
def load_rsa_public_key(keyname: str) -> crypto.PKey:
    with open(keyname + ".pub", "rb") as f:
        return crypto.load_publickey(crypto.FILETYPE_PEM, f.read())