import os

import pytest

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


CONFIG = """[DEFAULT]

hashcat_bin = /usr/bin/hashcat
rule = %(testdir)s/OneRule.rule
wordlist = %(testdir)s/words
hash_speed = 60000
db_uri = sqlite:///%(sqlite_path)s
"""


@pytest.fixture(scope='session')
def config_file():
    import tempfile
    fp = tempfile.NamedTemporaryFile(mode='w', delete=False,
                                     prefix="hch_configfile")
    db = tempfile.NamedTemporaryFile(mode='wb', delete=False,
                                     prefix="hch_sqlite_db")
    db.close()
    fp.write(CONFIG % {
        'testdir': SCRIPT_PATH,
        'sqlite_path': db.name,
    })
    fp.close()
    yield fp.name
    # TODO delete files?
