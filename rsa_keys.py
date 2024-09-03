# rsa_keys.py

import os
import random
from sympy import isprime
from hashlib import sha256, sha1

# Đường dẫn lưu trữ khóa
PUBLIC_KEY_FILE = "public_key.txt"
PRIVATE_KEY_FILE = "private_key.txt"

def generate_prime_candidate(length):
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=512):
    p = generate_prime_candidate(length)
    while not isprime(p):
        p = generate_prime_candidate(length)
    return p

def generate_keys(key_size=512):
    p = generate_prime_number(key_size // 2)
    q = generate_prime_number(key_size // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi_n)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key, p, q  # Trả về cả p và q

def save_key(key, filename):
    with open(filename, 'w') as f:
        f.write(f"{key[0]}\n{key[1]}")

def load_key(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        return (int(lines[0].strip()), int(lines[1].strip()))

def sign_message_with_key(message, private_key):
    d, n = private_key
    message_hash = int.from_bytes(sha256(message).digest(), 'big')
    signature = pow(message_hash, d, n)
    return signature

def verify_signature_with_key(message, signature, public_key, return_decrypted=False):
    e, n = public_key
    decrypted_hash = pow(signature, e, n)

    if return_decrypted:
        decrypted_message = decrypted_hash.to_bytes((decrypted_hash.bit_length() + 7) // 8, 'big')
        return decrypted_message.decode('utf-8', errors='ignore')

    if message:
        message_hash = int.from_bytes(sha256(message).digest(), 'big')
        return decrypted_hash == message_hash
    return False

def encrypt_message(public_key, message):
    e, n = public_key
    # Chuyển đổi message từ bytes sang số nguyên
    message_int = int.from_bytes(message, byteorder='big')
    if message_int >= n:
        raise ValueError("Message too long for the key size.")
    ciphertext = pow(message_int, e, n)
    return ciphertext

def decrypt_message(private_key, ciphertext):
    d, n = private_key
    decrypted_int = pow(ciphertext, d, n)
    # Tính số byte cần thiết
    num_bytes = (decrypted_int.bit_length() + 7) // 8
    decrypted_message = decrypted_int.to_bytes(num_bytes, byteorder='big')
    return decrypted_message
