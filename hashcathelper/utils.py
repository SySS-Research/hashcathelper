import re


def prcnt(a, b=None):
    """Return percentage rounded to two decimals"""
    if b:
        return int(a/b * 100 * 100)/100
    else:
        return int(a * 100)/100


def get_nthash(password):
    """Compute NT hash of password (must be bytes)"""
    import hashlib
    import binascii

    result = hashlib.new(
        'md4',
        password.decode(errors="replace").encode('utf-16le'),
    ).digest()
    return binascii.hexlify(result)


def get_lmhash(password):
    from Crypto.Cipher import DES
    import binascii

    if password is None:
        return bytes.fromhex('aad3b435b51404eeaad3b435b51404ee')

    LM_SECRET = b'KGS!@#$%'
    password_uppercase = password.upper()
    password_uppercase_bytes = password_uppercase.encode('ascii')
    password_uppercase_bytes_padded = \
        password_uppercase_bytes.ljust(14, b'\x00')
    password_chunk_1 = password_uppercase_bytes_padded[0:7]
    password_chunk_2 = password_uppercase_bytes_padded[7:]
    des_chunk_1 = DES.new(expand_DES_key(password_chunk_1), DES.MODE_ECB)
    des_chunk_2 = DES.new(expand_DES_key(password_chunk_2), DES.MODE_ECB)
    des_first_half = des_chunk_1.encrypt(LM_SECRET)
    des_second_half = des_chunk_2.encrypt(LM_SECRET)
    lm_hash = des_first_half + des_second_half
    result = binascii.hexlify(lm_hash)
    return result


# from impacket
def expand_DES_key(key):
    # Expand the key from a 7-byte password key into a 8-byte DES key
    key = key[:7]
    key += b'\x00'*(7-len(key))
    s = [
        (((key[0] >> 1) & 0x7f) << 1),
        (((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1),
        (((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1),
        (((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1),
        (((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1),
        (((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1),
        (((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1),
        ((key[6] & 0x7f) << 1),
    ]
    return b''.join([x.to_bytes(1, byteorder='big') for x in s])


PATTERN = re.compile(r'([^\\]+\\)?(?P<username>[^:]+):(?P<password>.*)$')


def parse_user_pass(line):
    """Takes line of a file and returns dictionary
    containing username and password.

    The format of the file must be like this:
        contoso.local\\username:Password123

    """

    regex = PATTERN.search(line)
    username = regex.group('username').lower()
    password = regex.group('password').lower()
    result = dict(
        username=username,
        password=password,
    )
    return result
