"""
Test the `ntlm` subcommand
"""

import os

import pytest


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


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


@pytest.fixture(scope='session')
def words():
    with open(os.path.join(SCRIPT_PATH, 'words'), 'r') as fp:
        words = fp.read()
    yield words.splitlines()


@pytest.fixture(scope='session')
def temp_dir():
    import tempfile
    yield tempfile.mkdtemp(prefix="hch_tempdir")


def create_pwdump(WORDS,
                  seed=0,
                  password_picks=20,
                  random_passwords=0,
                  user_eq_pass=0,
                  empty=0,
                  use_lm_hash=0,
                  domain='contoso.local',
                  weight_power=0):
    from hashcathelper.utils import get_nthash
    from hashcathelper.consts import LM_EMPTY
    import random
    import string

    random.seed(seed)
    passwords = []

    if password_picks:
        passwords += random.choices(
            WORDS,
            k=password_picks,
            weights=[1/(i/10+1)**weight_power for i, _ in enumerate(WORDS)],
        )
    if random_passwords:
        for _ in range(random_passwords):
            passwords.append(''.join(random.choices(string.ascii_uppercase,
                                                    k=16)))
    if empty:
        passwords += ['']*empty

    pw_dump = []
    cleartext = []

    for i, pw in enumerate(passwords):
        if i < use_lm_hash:
            lm_hash = get_lmhash(pw).decode()
        else:
            lm_hash = LM_EMPTY
        nt_hash = get_nthash(pw.encode())
        username = '%s\\User%05d' % (domain, i)
        pw_dump.append(
            '%s:%d:%s:%s:::' % (
                username, i, lm_hash, nt_hash
            )
        )
        cleartext.append('%s:%s' % (username, pw))
    for i in range(user_eq_pass):
        user = "User%05d" % len(pw_dump)
        username = "%s\\%s" % (domain, user)
        nt_hash = get_nthash(user.encode())
        pw_dump.append(
            '%s:%d:%s:%s:::' % (
                username, i, LM_EMPTY, nt_hash
            )
        )
        cleartext.append('%s:%s' % (username, user))

    return pw_dump, cleartext


def test_ntlm(temp_dir, words, config_file):
    import os

    from hashcathelper.__main__ import main

    random_passwords = 300
    pw_dump, cleartext = create_pwdump(
        words,
        password_picks=1000,
        random_passwords=random_passwords,
        user_eq_pass=20,
        empty=15,
        use_lm_hash=17,
        weight_power=2,
    )

    tmp_hash = os.path.join(temp_dir, 'hash.txt')
    with open(tmp_hash, 'w') as fp:
        fp.write('\n'.join(pw_dump)+'\n')

    main([
        '--config',
        config_file,
        'ntlm',
        '--skip-lm',
        tmp_hash,
    ])

    with open(tmp_hash + '.out', 'r') as fp:
        cracked_count = 0
        for line in fp.readlines():
            cracked_count += 1
            assert line[:-1] in cleartext

    assert cracked_count + random_passwords == len(cleartext)


def test_report():
    import json
    from hashcathelper.analytics import create_report

    hashfile = os.path.join(SCRIPT_PATH, 'hash.txt')
    outfile = os.path.join(SCRIPT_PATH, 'hash.txt.out')
    expected_f = os.path.join(SCRIPT_PATH, 'hash.txt.json')
    with open(expected_f, 'r') as fp:
        expected = json.load(fp)

    report = create_report(hashfile, outfile, degree_of_detail=3)
    report_json = report.json()
    del report_json['meta']
    print(json.dumps(report_json, indent=2))
    assert report_json == expected
