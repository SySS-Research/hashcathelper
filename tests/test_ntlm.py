"""
Test the `ntlm` subcommand
"""

import os

import pytest


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


CONFIG = """[DEFAULT]

hashcat_bin = /usr/bin/hashcat
rule = %(testdir)s/OneRule.rule
wordlist = %(testdir)s/words
hash_speed = 60000
"""


@pytest.fixture(scope='session')
def words():
    with open(os.path.join(SCRIPT_PATH, 'words'), 'r') as fp:
        words = fp.read()
    yield words.splitlines()


@pytest.fixture(scope='session')
def config_file():
    import tempfile
    fp = tempfile.NamedTemporaryFile(mode='w', delete=False,
                                     prefix="hch_configfile")
    fp.write(CONFIG % {'testdir': SCRIPT_PATH})
    fp.close()
    yield fp.name
    # TODO delete file?


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
    from hashcathelper.utils import get_nthash, get_lmhash
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
        nt_hash = get_nthash(pw.encode()).decode()
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
        nt_hash = get_nthash(user.encode()).decode()
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
        user_eq_pass=0,  # TODO hashcat can't crack these?!
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
    from hashcathelper.analytics import create_report

    hashfile = os.path.join(SCRIPT_PATH, 'hash.txt')
    outfile = os.path.join(SCRIPT_PATH, 'hash.txt.out')
    report = create_report(hashfile, outfile)
    expected = {
        'removed': 0,
        'user_equals_password': 0,
        'user_equals_password_percentage': 0.0, 'accounts': 1315,
        'total_accounts': 1315, 'cracked': 1015,
        'cracked_percentage': 77.18, 'lm_hash_count': 17,
        'lm_hash_count_percentage': 1.29,
        'cluster_count': dict([
            (2, 16), (3, 11), (4, 5), (5, 5), (6, 5), (7, 4),
            (9, 1), (11, 2), (12, 1), (13, 2), (14, 1),
            (15, 1), (18, 2), (19, 2), (23, 1), (25, 1),
            (28, 2), (30, 1), (37, 1), (40, 1), (53, 1),
            (54, 1), (59, 1), (69, 1), (74, 1), (137, 1)]),
        'unique': 318, 'unique_percentage': 24.18, 'empty_password':
        137, 'empty_password_percentage': 10.41,
        'average_password_length': 5.47, 'median_password_length':
        6, 'password_length_count': dict([
            (0, 137), (3, 7), (4, 28), (5, 106), (6, 411), (7, 183),
            (8, 143)]),
        'char_class_count': dict([
            (0, 137), (1, 570), (2, 308)]),
        'average_character_classes': 1.16,
        'top10_passwords': dict([
            ('', 137), ('12345', 74), ('abc123', 69),
            ('123456', 59), ('passwd', 54), ('password', 53),
            ('newpass', 40), ('notused', 37), ('Hockey', 30),
            ('Maddock', 28)]), 'top10_basewords':
        dict([
            ('abc', 71), ('passwd', 54), ('password', 53),
            ('internet', 41), ('newpass', 40), ('notused', 37),
            ('hockey', 30), ('mickey', 30), ('maddock', 28),
            ('newuser', 25)])
    }

    print(report)
    assert report == expected
