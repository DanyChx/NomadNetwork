import base64
import logging
import os

#Cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from shutil import move

class NomadWallet:
    def __init__(self, private_key=None, public_key=None, encrypted=False, encryption_key=None):
        if private_key != None:
            self.private_key = private_key
            self.public_key = self.private_key.public_key()
        elif public_key != None:
            self.public_key = public_key
        else:
            self.private_key = generate_private_key()
            self.public_key = self.private_key.public_key()
        store_public_key(self.public_key, './Keys/Public/public.pem')
        self.string_public_key = breakdown_pem_file('./Keys/Public/public.pem')
        os.remove('./Keys/Public/public.pem')

        self.encrypted = encrypted
        if self.encrypted:
            self.encryption_key = encryption_key

    def verify_signature(self, signature, plain_text):
        try:
            self.public_key.verify(
                signature=signature,
                data=plain_text.encode('utf-8'),
                padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def sign(self, plain_text):
        if self.private_key == None:
            return "No Private Key Provided"
        try:
            #Generate public key from private key
            public_key = self.private_key.public_key()

            # SIGN DATA/STRING
            signature = self.private_key.sign(
                data=plain_text.encode('utf-8'),
                padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256()
            )

            #Return signature
            return signature

        except UnsupportedAlgorithm:
            return "Signing Failed"

    def encrypt(self, plain_text):
        encrypted = encrypt(self.public_key, plain_text)
        return encrypted

    def decrypt(self, encrypted):
        if self.private_key == None:
            return "No Private Key Provided"
        decrypted = decrypt(self.private_key, encrypted)
        return decrypted

def generate_private_key():
    #   Create private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
        )

    #Return key
    return private_key

def store_private_key(file_name, private_key):
    #Generate PEM object for private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )

    #Write PEM object to file
    with open(file_name, 'wb') as f:
        f.write(pem)

def store_public_key(public_key, file_name):
    #Generate PEM object for public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    #Write PEM object to file
    with open(file_name, 'wb') as f:
        f.write(pem)

def read_private_key(file_name):
    with open(file_name, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )
    return private_key

def read_public_key(file_name):
    with open(file_name, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
            )
    return public_key

def text_public_key(public_key):
    public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
        )
    return public_key

def encrypt(public_key, message):
    message = message.encode('utf-8')

    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    return encrypted

def file_length(file_path):
    with open(file_path) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def encrypt_file_contents(public_key, file_path):
    with open(file_path,'r') as f:
        with open('./Temp/encrypted-file', 'w+') as t:
            line_number = 0
            while line_number <= file_length(file_path):
                line_number = f.tell()
                line_content = f.read()
                encrypted_line_content = str(encrypt(public_key,line_content))
                t.write(encrypted_line_content+'\n')
            f.close()
            t.close()
            move('./Temp/encrypted-file', file_path)

def decrypt(private_key, encrypted):
    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    original_message = original_message.decode('utf-8')
    return original_message

def decrypt_file_contents(private_key, file_path):
    with open(file_path,'r') as f:
        with open('./Temp/decrypted-file', 'w+') as t:
            line_number = 0
            while line_number <= file_length(file_path):
                line_number = f.tell()
                line_content = f.read()
                encrypted_line_content = str(decrypt(private_key,line_content))
                t.write(encrypted_line_content+'\n')
            f.close()
            t.close()
            move('./Temp/decrypted-file', file_path)

def remove_extension(file_name):
    without_extension = ''
    for char in file_name:
        if char != '.':
            without_extension = without_extension + char
        else:
            return without_extension

def breakdown_pem_file(file_name):
    data = [line.rstrip() for line in open(file_name)][1:-1]
    key = ""
    for line in data:
        line
        key = key + line
    return key

def craft_public_pem(key, file_name):
    with open(file_name, 'w') as file:
        file.write('-----BEGIN PUBLIC KEY-----\n')
        index = 0
        line = key[index]
        while index < len(key) - 1:
            index = index + 1
            if index % 64 == 0 or index == len(key):
                file.write(line + '\n')
                line = ''
            line = line + key[index]
        file.write(line + '\n')

        file.write('-----END PUBLIC KEY-----\n')

def craft_private_pem(key, file_name):
    with open(file_name, 'w') as file:
        file.write('-----BEGIN PRIVATE KEY-----\n')
        index = 0
        line = key[index]
        while index < len(key) - 1:
            index = index + 1
            if index % 64 == 0 or index == len(key):
                file.write(line + '\n')
                line = ''
            line = line + key[index]
        file.write(line + '\n')

        file.write('-----END PRIVATE KEY-----\n')

def shard_file(file_path, number_of_shards=3, shard_size=10, min_shard_size=1, max_shard_size=256000, dest='./'):
    with open(file_path, 'r+') as f:
        contents = f.read()
        file_length = len(contents)
        file_name = remove_extension(os.path.basename(f.name))
        char_index = 0

        next_shard_index = char_index + shard_size
        shard_contents = ''
        while char_index < file_length:
            with open(dest+file_name+str(char_index), 'w+') as shard:
                for line in f:
                    for ch in line:
                        if char_index != next_shard_index:
                            shard_contents = shard_contents + ch
                            char_index = char_index + 1
                        else:
                            shard.write(shard_contents)
                            shard.close()
                            if char_index != file_length - 1:
                                shard=open(dest+file_name+str(char_index), 'w+')
                                shard_contents= '' + ch
                                if char_index + shard_size >= file_length:
                                    next_shard_index = file_length - 1
                                else:
                                    next_shard_index = char_index + shard_size
                                char_index = char_index + 1
                        if char_index == file_length:
                            break
                    if char_index == file_length:
                        break
            shard.close()
