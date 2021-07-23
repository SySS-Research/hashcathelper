#!/usr/bin/env python3
# Adrian Vollmer, SySS GmbH, 2021


import argparse
import configparser
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile

__version__ = '0.1'


NT_RULESET = os.path.join(os.path.dirname(__file__), 'toggles-lm-ntlm.rule')

# Format: (name, speed factor)
HASH_TYPES = {
    900: "MD4",
    0: ("MD5", 1),
    100: "SHA1",
    1300: "SHA2-224",
    1400: "SHA2-256",
    10800: "SHA2-384",
    1700: "SHA2-512",
    17300: "SHA3-224",
    17400: "SHA3-256",
    17500: "SHA3-384",
    17600: "SHA3-512",
    6000: "RIPEMD-160",
    600: "BLAKE2b-512",
    11700: "GOST R 34.11-2012 (Streebog) 256-bit, big-endian",
    11800: "GOST R 34.11-2012 (Streebog) 512-bit, big-endian",
    6900: "GOST R 34.11-94",
    5100: "Half MD5",
    18700: "Java Object hashCode()",
    17700: "Keccak-224",
    17800: "Keccak-256",
    17900: "Keccak-384",
    18000: "Keccak-512",
    6100: "Whirlpool",
    10100: "SipHash",
    10: "md5($pass.$salt)",
    20: "md5($salt.$pass)",
    3800: "md5($salt.$pass.$salt)",
    3710: "md5($salt.md5($pass))",
    4110: "md5($salt.md5($pass.$salt))",
    4010: "md5($salt.md5($salt.$pass))",
    40: "md5($salt.utf16le($pass))",
    2600: "md5(md5($pass))",
    3910: "md5(md5($pass).md5($salt))",
    4400: "md5(sha1($pass))",
    4300: "md5(strtoupper(md5($pass)))",
    30: "md5(utf16le($pass).$salt)",
    110: "sha1($pass.$salt)",
    120: "sha1($salt.$pass)",
    4900: "sha1($salt.$pass.$salt)",
    4520: "sha1($salt.sha1($pass))",
    140: "sha1($salt.utf16le($pass))",
    19300: "sha1($salt1.$pass.$salt2)",
    14400: "sha1(CX)",
    4700: "sha1(md5($pass))",
    18500: "sha1(md5(md5($pass)))",
    4500: "sha1(sha1($pass))",
    130: "sha1(utf16le($pass).$salt)",
    1410: "sha256($pass.$salt)",
    1420: "sha256($salt.$pass)",
    1440: "sha256($salt.utf16le($pass))",
    1430: "sha256(utf16le($pass).$salt)",
    1710: "sha512($pass.$salt)",
    1720: "sha512($salt.$pass)",
    1740: "sha512($salt.utf16le($pass))",
    1730: "sha512(utf16le($pass).$salt)",
    19500: "Ruby on Rails Restful-Authentication",
    50: "HMAC-MD5 (key = $pass)",
    60: "HMAC-MD5 (key = $salt)",
    150: "HMAC-SHA1 (key = $pass)",
    160: "HMAC-SHA1 (key = $salt)",
    1450: "HMAC-SHA256 (key = $pass)",
    1460: "HMAC-SHA256 (key = $salt)",
    1750: "HMAC-SHA512 (key = $pass)",
    1760: "HMAC-SHA512 (key = $salt)",
    11750: "HMAC-Streebog-256 (key = $pass), big-endian",
    11760: "HMAC-Streebog-256 (key = $salt), big-endian",
    11850: "HMAC-Streebog-512 (key = $pass), big-endian",
    11860: "HMAC-Streebog-512 (key = $salt), big-endian",
    11500: "CRC32",
    14100: "3DES (PT = $salt, key = $pass)",
    14000: "DES (PT = $salt, key = $pass)",
    15400: "ChaCha20",
    14900: "Skip32 (PT = $salt, key = $pass)",
    11900: "PBKDF2-HMAC-MD5",
    12000: "PBKDF2-HMAC-SHA1",
    10900: "PBKDF2-HMAC-SHA256",
    12100: "PBKDF2-HMAC-SHA512",
    8900: "scrypt",
    400: "phpass",
    16900: "Ansible Vault",
    12001: "Atlassian (PBKDF2-HMAC-SHA1)",
    16100: "TACACS+",
    11400: "SIP digest authentication (MD5)",
    5300: "IKE-PSK MD5",
    5400: "IKE-PSK SHA1",
    2500: "WPA-EAPOL-PBKDF2",
    2501: "WPA-EAPOL-PMK",
    16800: "WPA-PMKID-PBKDF2",
    16801: "WPA-PMKID-PMK",
    7300: "IPMI2 RAKP HMAC-SHA1",
    10200: "CRAM-MD5",
    4800: "iSCSI CHAP authentication, MD5(CHAP)",
    16500: "JWT (JSON Web Token)",
    7500: "Kerberos 5 AS-REQ Pre-Auth etype 23",
    18200: "Kerberos 5 AS-REP etype 23",
    13100: "Kerberos 5 TGS-REP etype 23 (RC4-HMAC-MD5)",
    19600: "Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96)",
    19700: "Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96)",
    5500: "NetNTLMv1 / NetNTLMv1+ESS",
    5600: "NetNTLMv2",
    23: "Skype",
    11100: "PostgreSQL CRAM (MD5)",
    11200: "MySQL CRAM (SHA1)",
    8500: "RACF",
    6300: "AIX {smd5}",
    6700: "AIX {ssha1}",
    6400: "AIX {ssha256}",
    6500: "AIX {ssha512}",
    3000: "LM",
    19000: "QNX /etc/shadow (MD5)",
    19100: "QNX /etc/shadow (SHA256)",
    19200: "QNX /etc/shadow (SHA512)",
    15300: "DPAPI masterkey file v1",
    15900: "DPAPI masterkey file v2",
    7200: "GRUB 2",
    12800: "MS-AzureSync PBKDF2-HMAC-SHA256",
    12400: "BSDi Crypt, Extended DES",
    1000: "NTLM",
    122: "macOS v10.4, macOS v10.5, MacOS v10.6",
    1722: "macOS v10.7",
    7100: "macOS v10.8+ (PBKDF2-SHA512)",
    9900: "Radmin2",
    5800: "Samsung Android Password/PIN",
    3200: "bcrypt $2*$, Blowfish (Unix)",
    500: "md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)",
    1500: "descrypt, DES (Unix), Traditional DES",
    7400: "sha256crypt $5$, SHA256 (Unix)",
    1800: "sha512crypt $6$, SHA512 (Unix)",
    13800: "Windows Phone 8+ PIN/password",
    2410: "Cisco-ASA MD5",
    9200: "Cisco-IOS $8$ (PBKDF2-SHA256)",
    9300: "Cisco-IOS $9$ (scrypt)",
    5700: "Cisco-IOS type 4 (SHA256)",
    2400: "Cisco-PIX MD5",
    8100: "Citrix NetScaler",
    1100: "Domain Cached Credentials (DCC), MS Cache",
    2100: "Domain Cached Credentials 2 (DCC2), MS Cache 2",
    7000: "FortiGate (FortiOS)",
    125: "ArubaOS",
    501: "Juniper IVE",
    22: "Juniper NetScreen/SSG (ScreenOS)",
    15100: "Juniper/NetBSD sha1crypt",
    131: "MSSQL (2000)",
    132: "MSSQL (2005)",
    1731: "MSSQL (2012, 2014)",
    12: "PostgreSQL",
    3100: "Oracle H: Type (Oracle 7+)",
    112: "Oracle S: Type (Oracle 11+)",
    12300: "Oracle T: Type (Oracle 12+)",
    200: "MySQL323",
    300: "MySQL4.1/MySQL5",
    8000: "Sybase ASE",
    1421: "hMailServer",
    8300: "DNSSEC (NSEC3)",
    16400: "CRAM-MD5 Dovecot",
    1411: "SSHA-256(Base64), LDAP {SSHA256}",
    1711: "SSHA-512(Base64), LDAP {SSHA512}",
    15000: "FileZilla Server >= 0.9.55",
    12600: "ColdFusion 10+",
    1600: "Apache $apr1$ MD5, md5apr1, MD5 (APR)",
    141: "Episerver 6.x < .NET 4",
    1441: "Episerver 6.x >= .NET 4",
    101: "nsldap, SHA-1(Base64), Netscape LDAP SHA",
    111: "nsldaps, SSHA-1(Base64), Netscape LDAP SSHA",
    7700: "SAP CODVN B (BCODE)",
    7701: "SAP CODVN B (BCODE) from RFC_READ_TABLE",
    7800: "SAP CODVN F/G (PASSCODE)",
    7801: "SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE",
    10300: "SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
    133: "PeopleSoft",
    13500: "PeopleSoft PS_TOKEN",
    8600: "Lotus Notes/Domino 5",
    8700: "Lotus Notes/Domino 6",
    9100: "Lotus Notes/Domino 8",
    12200: "eCryptfs",
    14600: "LUKS",
    13711: "VeraCrypt RIPEMD160 + XTS 512 bit",
    13712: "VeraCrypt RIPEMD160 + XTS 1024 bit",
    13713: "VeraCrypt RIPEMD160 + XTS 1536 bit",
    13741: "VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode",
    13742: "VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode",
    13743: "VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode",
    13751: "VeraCrypt SHA256 + XTS 512 bit",
    13752: "VeraCrypt SHA256 + XTS 1024 bit",
    13753: "VeraCrypt SHA256 + XTS 1536 bit",
    13761: "VeraCrypt SHA256 + XTS 512 bit + boot-mode",
    13762: "VeraCrypt SHA256 + XTS 1024 bit + boot-mode",
    13763: "VeraCrypt SHA256 + XTS 1536 bit + boot-mode",
    13721: "VeraCrypt SHA512 + XTS 512 bit",
    13722: "VeraCrypt SHA512 + XTS 1024 bit",
    13723: "VeraCrypt SHA512 + XTS 1536 bit",
    13771: "VeraCrypt Streebog-512 + XTS 512 bit",
    13772: "VeraCrypt Streebog-512 + XTS 1024 bit",
    13773: "VeraCrypt Streebog-512 + XTS 1536 bit",
    13731: "VeraCrypt Whirlpool + XTS 512 bit",
    13732: "VeraCrypt Whirlpool + XTS 1024 bit",
    13733: "VeraCrypt Whirlpool + XTS 1536 bit",
    16700: "FileVault 2",
    12900: "Android FDE (Samsung DEK)",
    8800: "Android FDE <= 4.3",
    18300: "Apple File System (APFS)",
    6211: "TrueCrypt RIPEMD160 + XTS 512 bit",
    6212: "TrueCrypt RIPEMD160 + XTS 1024 bit",
    6213: "TrueCrypt RIPEMD160 + XTS 1536 bit",
    6241: "TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode",
    6242: "TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode",
    6243: "TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode",
    6221: "TrueCrypt SHA512 + XTS 512 bit",
    6222: "TrueCrypt SHA512 + XTS 1024 bit",
    6223: "TrueCrypt SHA512 + XTS 1536 bit",
    6231: "TrueCrypt Whirlpool + XTS 512 bit",
    6232: "TrueCrypt Whirlpool + XTS 1024 bit",
    6233: "TrueCrypt Whirlpool + XTS 1536 bit",
    10400: "PDF 1.1 - 1.3 (Acrobat 2 - 4)",
    10410: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1",
    10420: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2",
    10500: "PDF 1.4 - 1.6 (Acrobat 5 - 8)",
    10600: "PDF 1.7 Level 3 (Acrobat 9)",
    10700: "PDF 1.7 Level 8 (Acrobat 10 - 11)",
    9400: "MS Office 2007",
    9500: "MS Office 2010",
    9600: "MS Office 2013",
    9700: "MS Office <= 2003 $0/$1, MD5 + RC4",
    9710: "MS Office <= 2003 $0/$1, MD5 + RC4, collider #1",
    9720: "MS Office <= 2003 $0/$1, MD5 + RC4, collider #2",
    9800: "MS Office <= 2003 $3/$4, SHA1 + RC4",
    9810: "MS Office <= 2003 $3, SHA1 + RC4, collider #1",
    9820: "MS Office <= 2003 $3, SHA1 + RC4, collider #2",
    18400: "Open Document Format (ODF) 1.2 (SHA-256, AES)",
    18600: "Open Document Format (ODF) 1.1 (SHA-1, Blowfish)",
    16200: "Apple Secure Notes",
    15500: "JKS Java Key Store Private Keys (SHA1)",
    6600: "1Password, agilekeychain",
    8200: "1Password, cloudkeychain",
    9000: "Password Safe v2",
    5200: "Password Safe v3",
    6800: "LastPass + LastPass sniffed",
    13400: "KeePass 1 (AES/Twofish) and KeePass 2 (AES)",
    11300: "Bitcoin/Litecoin wallet.dat",
    16600: "Electrum Wallet (Salt-Type 1-2)",
    12700: "Blockchain, My Wallet",
    15200: "Blockchain, My Wallet, V2",
    18800: "Blockchain, My Wallet, Second Password (SHA256)",
    16300: "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256",
    15600: "Ethereum Wallet, PBKDF2-HMAC-SHA256",
    15700: "Ethereum Wallet, SCRYPT",
    11600: "7-Zip",
    12500: "RAR3-hp",
    13000: "RAR5",
    14700: "iTunes backup < 10.0",
    14800: "iTunes backup >= 10.0",
    13600: "WinZip",
    18900: "Android Backup",
    13200: "AxCrypt",
    13300: "AxCrypt in-memory SHA1",
    8400: "WBB3 (Woltlab Burning Board)",
    2611: "vBulletin < v3.8.5",
    2711: "vBulletin >= v3.8.5",
    2612: "PHPS",
    121: "SMF (Simple Machines Forum) > v1.1",
    3711: "MediaWiki B type",
    4521: "Redmine",
    10000: "Django (PBKDF2-SHA256)",
    124: "Django (SHA-1)",
    11: "Joomla < 2.5.18",
    13900: "OpenCart",
    11000: "PrestaShop",
    16000: "Tripcode",
    7900: "Drupal7",
    21: "osCommerce, xt:Commerce",
    4522: "PunBB",
    2811: "MyBB 1.2+, IPB2+ (Invision Power Board)",
    18100: "TOTP (HMAC-SHA1)",
    2000: "STDOUT",
    99999: "Plaintext",
}

FAVORITE_HASHTYPES = {
    "AD": [1000, 1100, 3000, 5600, 13100, 19700],
    "Web": [0, 100, 900, 1700, 3200, 8900, 12000],
}

POPULAR_WORDLISTS = [
    'Bitweasel',
    'crackstation-human-only.txt',
    'wikipedia_de-20160629.txt',
    'wikipedia_en-20160629.txt',
    'duden_german.txt',
    'linkedin.dic',
    '10-million-passwords.txt',
    'Openwall',
    'public_leaks/Rockyou_list_original.txt',
]

POPULAR_RULES = [
    'best64.rule',
    'dive.rule',
    'OneRule.rule',
]


def parse_args():
    parser = argparse.ArgumentParser(
        description='Wrapper for hashcat which helps you choose suitable '
        'wordlists and rules',
    )

    parser.add_argument(
        '-v', '--version', action='version',
        version='hashcathelper' + __version__
    )

    parser.add_argument(
        '-c', '--config',
        type=str,
        help="path to config file; if empty we will try ./hashcathelper.conf"
        " and ${XDG_CONFIG_HOME:~}/hashcathelper/hashcathelper.conf in that"
        " order",
    )

    parser.add_argument(
        dest='hashfile',
        help="path to the file containing the hashes",
    )

    parser.add_argument(
        dest='passwordfile',
        nargs='?',
        default=None,
        help="path to the output file with the results; if it already"
             " exists, we will skip straight to creating the report",
    )

    parser.add_argument(
        '-a', '--active-accounts',
        help="path to a file containing active accounts "
             "(one per line; without domain or UPN; case insensitive); "
             "if empty, all accounts are assumed to be active"
    )

    return parser.parse_args()


def parse_config(path):
    config_parser = configparser.ConfigParser()
    if not path:
        path = 'hashcathelper.conf'
        #  if not os.path.exists(path):
        #      path = xdg.something TODO
    config_parser.read(path)
    global config
    attrs = 'rule wordlist hashcat_bin hash_speed'.split()
    for a in attrs:
        assert config_parser['DEFAULT'], 'Attribute undefined: ' + a
    Config = collections.namedtuple('Config', attrs)
    config = Config(
        *[config_parser['DEFAULT'].get(a) for a in attrs]
    )


def hashcat(hashfile, hashtype, wordlists=[], ruleset=None, pwonly=True,
            directory='.'):
    """
    Run hashcat as a subprocess

    Returns: name of a file containing the stdout of hashcat with ``--show``
    """

    base_command = [
        config.hashcat_bin,
        hashfile,
        '--username',
        '-m', str(hashtype),
    ]
    command = base_command + ['--outfile-autohex-disable']
    if wordlists:
        command = command + ['-a', '0'] + wordlists
        # Attack mode wordlist
        if ruleset:
            command = command + ['-r', ruleset]
    else:
        # Attack mode brute force, all combinations of 7 character passwords
        # (This assumes cracking LM hashes)
        command = command + ['-a', '3', '-i', '?a?a?a?a?a?a?a',
                             '--increment-min', '1', '--increment-max', '7']

    p = subprocess.Popen(
        command,
        stdout=sys.stdout,
        stderr=subprocess.STDOUT,
    )
    p.communicate()

    # Retrieve result
    show_command = base_command + ['--show']
    show_command += ['--outfile-format', '2']

    p = subprocess.Popen(
        show_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    passwords, _ = p.communicate()

    result = tempfile.NamedTemporaryFile(delete=False, dir=directory)
    for p in passwords.splitlines():
        if pwonly:
            # Remove username
            p = b':'.join(p.split(b':')[1:]) + b'\n'
        # Write rest of the line to the result file
        result.write(p)
    result.close()
    return result.name


def crack_pwdump(hashfile, directory, extra_words=[]):
    """
    Crack the hashes in a pwdump file.

    Files like this are generated by Impacket's secretsdump or Meterpreter's
    pwdump, for example. A line looks like this:

        <USER NAME>:<USER ID>:<LM HASH>:<NT HASH>:::

    First, the LM hashes are cracked in incremental mode. Then, the results
    are used with an NTLM rule set to crack the corresponding NT hashes.
    Last, the results are added to the crackstation wordlist and mangled
    with the OneRule rule set.
    """

    lm_result = hashcat(
        hashfile,
        hashtype=3000,
        directory=directory,
    )

    nt_result = hashcat(
        hashfile,
        hashtype=1000,
        ruleset=NT_RULESET,
        wordlists=[lm_result],
        directory=directory,
    )

    final_result = hashcat(
        hashfile,
        hashtype=1000,
        ruleset=config.rule,
        wordlists=[nt_result, config.wordlist],
        pwonly=False,
        directory=directory,
    )
    return final_result


def median(lst):
    sortedLst = sorted(lst)
    lstLen = len(lst)
    index = (lstLen - 1) // 2

    if (lstLen % 2):
        return sortedLst[index]
    else:
        return (sortedLst[index] + sortedLst[index + 1])/2.0


def average(lst):
    return sum(lst)/len(lst)


def get_top_basewords(passwords):
    counts = collections.Counter()
    for p in passwords:
        if not p:
            continue
        # Convert to lower case
        p = p.lower()

        # Remove special chars and digits from beginning and end
        p = re.sub('[0-9!@#$%^&*()=_+~{}|"? ><,./\\\'[\\]-]*$', '', p)
        p = re.sub('^[0-9!@#$%^&*()=_+~{}|" ?><,./\\\'[\\]-]*', '', p)

        # De-leet-ify
        p = p.replace('!', 'i')
        p = p.replace('1', 'i')
        p = p.replace('0', 'o')
        p = p.replace('3', 'e')
        p = p.replace('4', 'a')
        p = p.replace('@', 'a')
        p = p.replace('+', 't')
        p = p.replace('$', 's')
        p = p.replace('5', 's')

        # Remove remaining special chars
        p = re.sub('[!@#$%^&*()=_+~{}|"?><,./\\\'[\\]-]', '', p)

        # Forget this if it's empty by now
        if not p:
            continue

        # Is it multiple words? Get the longest
        p = sorted(p.split(), key=len)[-1]

        # If there are digits left (i.e. it's not a word) or the word is
        # empty, we're not interested anymore
        if not re.search('[0-9]', p) and p:
            counts.update([p])

    # Remove basewords shorter than 3 characters or occurance less than 2
    for k in counts.copy():
        if counts[k] == 1 or len(k) < 3:
            del counts[k]
    return counts.most_common(10)


def get_char_classes(passwords):
    def get_character_classes(s):
        upper = False
        lower = False
        digits = False
        chars = False
        if re.search('[A-Z]', s):
            upper = True
        if re.search('[a-z]', s):
            lower = True
        if re.search('[0-9]', s):
            digits = True
        if re.search('[^A-Za-z0-9]', s):
            chars = True
        result = sum([upper, lower, digits, chars])
        return result

    counts = collections.Counter()
    for p in passwords:
        classes = get_character_classes(p)
        counts.update([classes])
    return counts


def create_report(hash_file, password_file=None, active_accounts=None,
                  pretty=True):
    print("Creating report...")

    # Load data from files
    if password_file:
        with open(password_file, 'r', encoding="utf-8", errors="replace") as f:
            passwords_content = f.read()
    else:
        passwords_content = ''

    with open(hash_file, 'r') as f:
        hashfile_content = f.read()

    hashes = hashfile_content.splitlines()
    account_plus_password = passwords_content.splitlines()

    pattern = re.compile(r'([^\\]+\\)?(?P<name>[^:]+):.*$')

    def get_account_name(line):
        name = pattern.search(line).group('name').lower()
        return name

    if active_accounts:
        print("Only taking active accounts into consideration")
        with open(active_accounts, 'r') as f:
            active_accounts = f.read().lower().splitlines()
        account_plus_password = [p for p in account_plus_password
                                 if get_account_name(p) in active_accounts]
        hashes = [h for h in hashes
                  if get_account_name(h) in active_accounts]
    else:
        print("Assuming all accounts are active")

    # Analyze hashes only
    total = len(hashes)
    cracked = len(account_plus_password)
    lm_hash_count = 0
    for line in hashes:
        if ':aad3b435b51404eeaad3b435b51404ee:' not in line:
            lm_hash_count += 1
    nt_hashes = collections.Counter(line.split(':')[3] for line in hashes)
    empty_nt_hash_count = nt_hashes['31d6cfe0d16ae931b73c59d7e0c089c0']
    del nt_hashes['31d6cfe0d16ae931b73c59d7e0c089c0']
    hash_clusters = dict(c for c in nt_hashes.most_common() if c[1] > 1)
    cluster_count = collections.Counter(c for c in hash_clusters.values()
                                        if c > 1)

    # Analyze passwords
    passwords = [':'.join(line.split(':')[1:])
                 for line in account_plus_password]
    lengths = [len(p) for p in passwords]
    average_password_length = average(lengths)
    median_password_length = median(lengths)
    password_length_count = dict(collections.Counter(lengths))

    top10_passwords = dict(collections.Counter(passwords).most_common(10))
    top10_basewords = dict(get_top_basewords(passwords))
    char_class_count = dict(get_char_classes(passwords))

    # Create Report
    report = {
        'filename': hash_file,
        'total': total,
        'cracked': cracked,
        'cracked_percentage': cracked/total*100.,
        'lm_hash_count': lm_hash_count,
        'lm_hash_count_percentage': lm_hash_count/total*100.,
        #  'hash_clusters': hash_clusters,  # is large
        'empty_nt_hash_count': empty_nt_hash_count,
        'cluster_count': dict(cluster_count),
        'median_cluster_count': median(cluster_count.values()),
        'average_cluster_count': average(cluster_count.values()),
        'average_password_length': average_password_length,
        'median_password_length': median_password_length,
        'password_length_count': password_length_count,
        'top10_passwords': top10_passwords,
        'top10_basewords': top10_basewords,
        'char_class_count': char_class_count,
    }

    if pretty:
        outstring = """\
Total: %(total)d
Cracked: %(cracked)d (%(cracked_percentage).2f)
LM Hashes: %(lm_hash_count)d (%(lm_hash_count_percentage).2f)
    """ % report
        print(outstring)
    else:
        print(report)


def main():
    args = parse_args()

    if os.path.exists(args.passwordfile):
        print("Password file already exists, skipping hashcat run")
    else:
        parse_config(args.config)
        TEMP_DIR = tempfile.TemporaryDirectory(
            prefix=args.hashfile+'_hch_',
            dir='.',
        )
        password_file = crack_pwdump(args.hashfile, TEMP_DIR.name)
        shutil.copy(password_file, args.passwordfile)

    create_report(
        args.hashfile,
        args.passwordfile,
        active_accounts=args.active_accounts,
        pretty=False,
    )


if __name__ == "__main__":
    main()
