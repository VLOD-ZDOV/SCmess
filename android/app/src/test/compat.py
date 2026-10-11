"""Cross-check against the Python implementations (desktop SCmess.py and the old Kivy app).

  python3 compat.py make   <dir>   write vectors that CompatTest decrypts
  python3 compat.py verify <dir>   decrypt what CompatTest wrote into <dir>/kotlin
"""
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
TEXT = "Привет, мир! 🔐 SCmess"
b64 = lambda b: base64.b64encode(b).decode()


def slot(pub):
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:32]


def seal(text):
    key, iv = os.urandom(32), os.urandom(12)
    out = AESGCM(key).encrypt(iv, text.encode(), None)
    return key, iv, out[:-16], out[-16:]


def make(d):
    os.makedirs(d, exist_ok=True)
    a = rsa.generate_private_key(65537, 2048)
    b = rsa.generate_private_key(65537, 2048)
    with open(f"{d}/key_a.pem", "wb") as f:  # PKCS#8, as both Python apps write it
        f.write(a.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    with open(f"{d}/key_b.pem", "wb") as f:  # PKCS#1 ("RSA PRIVATE KEY")
        f.write(b.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()))

    key, iv, ct, tag = seal(TEXT)
    with open(f"{d}/single.json", "w") as f:
        json.dump({"aes_key": b64(a.public_key().encrypt(key, OAEP)), "iv": b64(iv),
                   "tag": b64(tag), "ciphertext": b64(ct)}, f)

    key, iv, ct, tag = seal(TEXT)
    with open(f"{d}/group_fp.json", "w") as f:  # Kivy app: fingerprint slots
        json.dump({"type": "group_message_gcm", "iv": b64(iv), "tag": b64(tag), "ciphertext": b64(ct),
                   "keys": {slot(k.public_key()): b64(k.public_key().encrypt(key, OAEP)) for k in (a, b)}}, f)

    key, iv, ct, tag = seal(TEXT)
    with open(f"{d}/group_names.json", "w") as f:  # desktop: user-name slots + sender
        json.dump({"type": "group_message_gcm", "sender": "desk", "iv": b64(iv), "tag": b64(tag),
                   "ciphertext": b64(ct), "keys": {"bob": b64(b.public_key().encrypt(key, OAEP))}}, f, indent=4)

    with open(f"{d}/legacy.txt", "w") as f:
        f.write(b64(b.public_key().encrypt(TEXT.encode(), OAEP)))

    plain = os.urandom(300_000)
    with open(f"{d}/plain.bin", "wb") as f:
        f.write(plain)

    key, iv = os.urandom(32), os.urandom(12)
    out = AESGCM(key).encrypt(iv, plain, None)
    ek = a.public_key().encrypt(key, OAEP)
    with open(f"{d}/file_v2.enc", "wb") as f:  # Kivy app v1.7
        f.write(len(ek).to_bytes(2, "big") + ek + iv + out)

    key, iv = os.urandom(32), os.urandom(12)
    out = AESGCM(key).encrypt(iv, plain, None)
    with open(f"{d}/file_v1.enc", "wb") as f:  # desktop
        f.write(b.public_key().encrypt(key, OAEP) + iv + out[-16:] + out[:-16])


def verify(d):
    k = f"{d}/kotlin"
    load = lambda p: serialization.load_pem_private_key(open(p, "rb").read(), None)
    a, b = load(f"{d}/key_a.pem"), load(f"{d}/key_b.pem")

    m = json.load(open(f"{k}/single.json"))
    key = a.decrypt(base64.b64decode(m["aes_key"]), OAEP)
    ct = base64.b64decode(m["ciphertext"]) + base64.b64decode(m["tag"])
    assert AESGCM(key).decrypt(base64.b64decode(m["iv"]), ct, None).decode() == TEXT

    m = json.load(open(f"{k}/group.json"))
    assert m["type"] == "group_message_gcm" and set(m["keys"]) == {slot(a.public_key()), slot(b.public_key())}
    for priv in (a, b):
        key = priv.decrypt(base64.b64decode(m["keys"][slot(priv.public_key())]), OAEP)
        ct = base64.b64decode(m["ciphertext"]) + base64.b64decode(m["tag"])
        assert AESGCM(key).decrypt(base64.b64decode(m["iv"]), ct, None).decode() == TEXT

    assert b.decrypt(base64.b64decode(open(f"{k}/legacy.txt").read()), OAEP).decode() == TEXT

    raw = open(f"{k}/file.enc", "rb").read()  # same parsing as the Kivy app's decrypt_file_gcm
    n = int.from_bytes(raw[:2], "big")
    key = a.decrypt(raw[2:2 + n], OAEP)
    plain = AESGCM(key).decrypt(raw[2 + n:2 + n + 12], raw[2 + n + 12:], None)
    assert plain == open(f"{d}/plain.bin", "rb").read()
    print("python: all Kotlin outputs decrypt OK")


if __name__ == "__main__":
    {"make": make, "verify": verify}[sys.argv[1]](sys.argv[2])
