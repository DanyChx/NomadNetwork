import hashlib
from pki import NomadWallet
import random
import unicodedata
from termcolor import colored
import base64
import hashlib

def hash_it(x):
    sha = hashlib.sha256()
    if isinstance(x, str):
        sha.update(x.encode())
    else:
        sha.update(x.decode('utf-8').encode())
    return sha.hexdigest()

def generate_salt(salt_length, chars_allowed=0):
    #Build list of characters
    char_list = ''.join(chr(char) for char in range(65533) if unicodedata.category(chr(char))[0] in ('LMNPSZ'))
    if chars_allowed <= 0:
        chars_allowed = 65533
    #Generate a Salt with the specified length, using the first portion of the charcter list up to chars_allowed
    salt = ''.join([random.choice(char_list[:chars_allowed]) for i in range(salt_length)])
    #Return salt
    return salt

def make_simple_nonce(len):
        return generate_salt(salt_length=len)

def make_simple_scoop(size=5, len=16):
    scoop = []
    for _ in range(size):
        scoop.append(make_simple_nonce(len))
    return scoop

def plot_directory(plot_size):
    plot_size = int((plot_size * 1073741824)/2)
    with open('./Vault/nomad.plot', 'wb+') as plot_file:
        print(plot_size)
        for _ in range(plot_size):
            nonce = make_simple_nonce(16)
            plot_file.write((nonce+'\n').encode())
            print(f"Created Nonce #{_}. It should resemble the following; {nonce}")
        plot_file.close()

def mine_by_capacity(proof):
    with open ('./Vault/nomad.plot', 'rb') as plot_file:
        lines = plot_file.readlines()
        i = 0
        for nonce in lines:
            hashed_nonce = hash_it(nonce)
            #Define Previous Miner Wallet
            for scoop_nonce in proof['scoop']:
                if hashed_nonce == scoop_nonce:
                    scoop = [hash_it(nonce) for nonce in lines[i:i+5]]
                    return [True, {"nonce":nonce, "scoop":scoop}]
            i += 1
        return [False, 'Mining Unsuccessful']

def validate_proof(last_proof, current_proof):
    if hash_it(current_proof['nonce']) in last_proof['scoop'] and hash_it(current_proof['nonce']) in current_proof['scoop']:
        return [True, 'Proof validated successfully!']
    else:
        return [False, 'Invalid proof...']
