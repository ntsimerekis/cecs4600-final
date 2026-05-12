#!/usr/bin/env python3
import sys

from client import start_client
from crypto_helpers import *
from server import *

def main():
    if sys.argv[1] == 'generate':
        generate_and_save_rsa_key(sys.argv[2])
    elif sys.argv[1] == 'server':
        start_server(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == 'client':
        start_client(sys.argv[2], sys.argv[3], sys.argv[4], True if len(sys.argv) >= 6 and sys.argv[5] == 'with-corruption' else False)

if __name__ == '__main__':
    main()