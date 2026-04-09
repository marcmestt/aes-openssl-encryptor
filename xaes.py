#!/usr/bin/env python3

import sys
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Constantes que necesitamos para que sea compatible con openssl
MAGIC = b"Salted__"   # openssl siempre empieza el fichero con esto
SALT_SIZE = 8          # el salt ocupa 8 bytes
KEY_SIZE = 16          # AES-128 necesita una clave de 16 bytes
IV_SIZE = 16           # el IV también es de 16 bytes
ITERATIONS = 10000     # openssl usa 10000 iteraciones por defecto con -pbkdf2
BLOCK_BITS = 128       # tamaño de bloque de AES en bits


def derive_key_iv(password, salt):
    # A partir de la contraseña y el salt, generamos la clave y el IV
    # usamos PBKDF2 con SHA-256, que es lo mismo que hace openssl
    # el resultado son 32 bytes: los primeros 16 son la clave y los otros 16 el IV
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE + IV_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    key_iv = kdf.derive(password)
    return key_iv[:KEY_SIZE], key_iv[KEY_SIZE:]


def encrypt(password, plaintext):
    # generamos un salt aleatorio cada vez que ciframos
    # esto hace que el mismo fichero cifrado dos veces de resultados distintos
    salt = os.urandom(SALT_SIZE)

    # derivamos la clave y el IV a partir de la contraseña y el salt
    key, iv = derive_key_iv(password.encode("utf-8"), salt)

    # AES necesita que el mensaje sea múltiplo de 16 bytes, asi que añadimos padding
    padder = padding.PKCS7(BLOCK_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # ciframos con AES-128-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # el fichero cifrado tiene que empezar por "Salted__" + salt para ser compatible con openssl
    return MAGIC + salt + ciphertext


def decrypt(password, data):
    # comprobamos que el fichero empiece por "Salted__" si no es un error
    if not data.startswith(MAGIC):
        print("Error: el fichero no tiene el formato OpenSSL 'Salted__'.", file=sys.stderr)
        sys.exit(1)

    # extraemos el salt que esta entre los bytes 8 y 16
    salt = data[8:16]
    ciphertext = data[16:]

    # con la contraseña y el salt volvemos a derivar la misma clave y el mismo IV
    key, iv = derive_key_iv(password.encode("utf-8"), salt)

    # desciframos
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # quitamos el padding que añadimos al cifrar
    try:
        unpadder = padding.PKCS7(BLOCK_BITS).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        print("Error: contraseña incorrecta o fichero corrupto.", file=sys.stderr)
        sys.exit(1)

    return plaintext


def main():
    # el programa necesita 2 argumentos: la opción y la contraseña
    if len(sys.argv) != 3:
        print("Uso: xaes.py -e|-d \"contraseña\"", file=sys.stderr)
        print("  -e  Cifrar   (stdin -> stdout)", file=sys.stderr)
        print("  -d  Descifrar (stdin -> stdout)", file=sys.stderr)
        sys.exit(1)

    option = sys.argv[1]
    password = sys.argv[2]

    # leemos todo lo que llegue por la entrada estandar
    data = sys.stdin.buffer.read()

    if option == "-e":
        result = encrypt(password, data)
    elif option == "-d":
        result = decrypt(password, data)
    else:
        print(f"Error: opción desconocida '{option}'. Usa -e o -d.", file=sys.stderr)
        sys.exit(1)

    # escribimos el resultado por la salida estandar
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    main()