import socketserver

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from crypto_helpers import *

class ReceiveHandler(socketserver.BaseRequestHandler):
    def handle(self):
        private_key: RSAPrivateKey = self.server.private_key.to_cryptography_key()

        header_bytes = self.request.recv(528)
        aes_key, nonce, size = get_key_and_size_formatted_encrypted_message_header(header_bytes, private_key)

        ciphertext = self.request.recv(size)

        plaintext_bytes = decrypt_aes_message(aes_key, nonce, ciphertext)
        print(str(plaintext_bytes))

def start_server(my_keyname: str, their_keyname: str):

    with socketserver.TCPServer(("127.0.0.1", 9999), ReceiveHandler) as server:
        server.private_key = load_rsa_private_key(my_keyname)

        print("server started")
        server.serve_forever()