from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data):
    while len(data) % 16 != 0:
        data += b' '
    return data

def unpad(data):
    return data.rstrip(b' ')

def encrypt_method(image_path, output_path, key):
    with open(image_path, 'rb') as f:
        data = f.read()

    data = pad(data)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data)

    with open(output_path, 'wb') as f:
        f.write(iv + encrypted)

def decrypt_method(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        iv = f.read(16)
        encrypted = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted))

    with open(output_path, 'wb') as f:
        f.write(decrypted)

def generate_key(length):
    if length not in [16, 24, 32]:
        raise ValueError("Key length must be 16, 24, or 32 bytes.")
    return get_random_bytes(length)
