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


USER_PATTERN = re.compile(
    r'(?P<upn_suffix>[^\\]+\\)?(?P<username>[^:]+)$'
)
USER_PASS_PATTERN = re.compile(
    r'(?P<upn_suffix>[^\\]+\\)?(?P<username>[^:]+):(?P<password>.*)$'
)
PWDUMP_PATTERN = re.compile(
    r'((?P<upn_suffix>[^\\]+)\\)?(?P<username>[^:]+):'
    r'(?P<id>[0-9]+):(?P<lmhash>[a-f0-9]{32}):(?P<nthash>[a-f0-9]{32}):::'
    r'(?P<comment>.*)'
)


class User(object):
    attributes = 'username upn_suffix id lmhash nthash password comment'\
            .split()

    def __init__(self, line):
        for p in [
            PWDUMP_PATTERN,
            USER_PASS_PATTERN,
            USER_PATTERN,
        ]:
            m = p.search(line)
            if m:
                break
        if not m:
            raise ValueError("Could not parse line: %s" % line)

        for a in self.attributes:
            try:
                setattr(self, a, m.group(a).strip())
            except IndexError:
                # "no such group"
                setattr(self, a, None)

        if not self.username:
            raise ValueError("Could not parse line: %s" % line)

        # Set full_username; won't really be used though
        if self.upn_suffix:
            self.full_username = '%s\\%s' % (
                self.upn_suffix,
                self.username,
            )
        else:
            self.full_username = self.username

    def is_computer_account(self):
        return self.username.endswith('$')

    def __eq__(self, b):
        if isinstance(b, User):
            b = b.username
        if not isinstance(b, str):
            raise TypeError("Can't compare User object with type %s" %
                            type(b).__name__)
        return self.username.lower() == b.lower()
