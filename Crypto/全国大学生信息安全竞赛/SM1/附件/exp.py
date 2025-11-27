import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def read_files():
    with open("r", "r") as f: r = int(f.read())
    with open("ef", "r") as f: ef = base64.b64decode(f.read())
    with open("ps", "r") as f: ps = [int(line) for line in f]
    return r, ef, ps

def recover_choose(r, ps):
    positions = [(bin(p)[2:].zfill(512).rfind('1'), i) for i, p in enumerate(ps)]
    positions.sort(reverse=True)
    
    bchoose, current_r = [0]*512, r
    for pos, idx in positions:
        if (current_r >> (511-pos)) & 1:
            bchoose[idx] = 1
            current_r ^= ps[idx]
    
    return int(''.join(map(str, bchoose)), 2)

def decrypt_flag(choose, ef):
    key = hashlib.md5(choose.to_bytes(64, 'big')).digest()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())
    return cipher.decryptor().update(ef) + cipher.decryptor().finalize()

if __name__ == "__main__":
    r, ef, ps = read_files()
    choose = recover_choose(r, ps)
    flag = decrypt_flag(choose, ef)
    print(f"Flag: {flag.decode()}")