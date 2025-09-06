from ansible.errors import AnsibleError, AnsibleUndefinedVariable
from jinja2 import StrictUndefined
__metaclass__ = type

try:
    import passlib.hash, os, hashlib, binascii
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

def check_lib():
    if not HAS_LIB:
        raise AnsibleError('You need to install "passlib" prior to running '
                           'password_hash-based filters')

def doveadm_pw_hash(password):
    check_lib()
    if type(password) is StrictUndefined:
        raise AnsibleUndefinedVariable('Please pass a string into this password_hash-based filter')
    return passlib.hash.sha512_crypt.hash(password, rounds=5000)

def znc_makepass(password: str, iterations: int = 4096, salt_len: int = 16):
    # Generate random ASCII salt (printable)
    # We’ll draw from letters + digits for safety
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    salt = b"".join(bytes([alphabet[os.urandom(1)[0] % len(alphabet)]]) for _ in range(salt_len))

    # Compute SHA256(password + salt)
    m = hashlib.sha256()
    m.update(password.encode("utf-8"))
    m.update(salt)
    digest = m.hexdigest()

    block = (
        "<Pass password>\n"
        f"  Method = sha256\n"
        f"  Hash = {digest}\n"
        f"  Salt = {salt.decode('ascii')}\n"
        "</Pass>\n"
    )
    return block

class FilterModule(object):

    def filters(self):
        return {
            'doveadm_pw_hash': doveadm_pw_hash,
            'znc_makepass': znc_makepass,
        }
