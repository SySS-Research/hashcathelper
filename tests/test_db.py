"""
Test the `db` subcommand
"""

from collections import namedtuple
import os
import json
import random


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def test_submit(config_file, monkeypatch):
    from hashcathelper.__main__ import main
    from hashcathelper.subcommands import db
    from hashcathelper.args import parse_config
    from hashcathelper.sql import get_session, Report

    Answers = namedtuple(
        'Answers',
        'submitter_email wordlist rule_set hashcat_version',
    )
    answers = Answers(
        'foo@bar.com',
        'crackstation.txt',
        'OneRule.rule',
        'v6.0.1',
    )

    def mock_ask_questions(config):
        return answers

    monkeypatch.setattr(db, 'ask_questions', mock_ask_questions)
    config = parse_config(config_file)
    s = get_session(config.db_uri)

    outfile = os.path.join(SCRIPT_PATH, 'hash.txt.json')
    s.query(Report).delete()

    main([
        '--config',
        config_file,
        'db',
        'submit',
        outfile,
    ])

    r = s.query(Report).one()

    expected_f = os.path.join(SCRIPT_PATH, 'hash.txt.json')
    with open(expected_f, 'r') as fp:
        expected = json.load(fp)

    print(vars(r))
    assert r.total_accounts == expected['report']['accounts']
    assert r.submitter_email == answers.submitter_email

    # Test queries
    main([
        '--config',
        config_file,
        'db',
        'stats',
        '1',
    ])

    main([
        '--config',
        config_file,
        'db',
        'stats',
    ])

    main([
        '--config',
        config_file,
        'db',
        'query',
    ])


def create_report(total_accounts, seed=0):
    random.seed(seed)
    largest_cluster = int(abs(random.gauss(total_accounts/10,
                                           total_accounts/50)))
    average_password_length = abs(random.gauss(8, 3))

    result = {
      "meta": {
        "timestamp": "2021-08-12 11:12:43.706036"
      },
      "report": {
        "removed": 0,
        "user_equals_password": [
          0,
          0.0
        ],
        "accounts": total_accounts,
        "total_accounts": total_accounts,
        "cluster_count": {},
        "average_password_length": average_password_length,
        "median_password_length": 6,
        "password_length_count": {},
        "char_class_count": {},
        "average_character_classes": 0
      },
      "sensitive": {
        "top10_passwords": {},
        "top10_basewords": {
          "baseword1": largest_cluster,
        }
      },
    }

    # Fill in values with percentages
    ta = total_accounts
    for a, parameters in {
        'user_equals_password': (ta/100, ta/50),
        'lm_hash_count': (ta/30, ta/50),
        'cracked': (ta/3, ta/5),
        'unique': (ta*.8, ta*.3),
        'empty_password': (ta/100, ta/50),
    }.items():
        val = min(int(abs(random.gauss(*parameters))), ta)
        result['report'][a] = [val, 100*val/ta]

    return result


def test_stats(config_file, monkeypatch):
    from hashcathelper.__main__ import main
    from hashcathelper.args import parse_config
    from hashcathelper.sql import get_session, Report, submit
    config = parse_config(config_file)
    s = get_session(config.db_uri)
    random.seed(0)
    for i in range(100):
        data = create_report(random.randint(200, 200000), seed=i)
        submit(s, 'foo', 'wordlist', 'rule', '0.0', data)

    s.query(Report).all()

    main([
        '--config',
        config_file,
        'db',
        'stats',
    ])
