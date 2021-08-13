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
    assert r.accounts == expected['report']['accounts']
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


def create_report(accounts, seed=0):
    random.seed(seed)
    largest_cluster = int(abs(random.gauss(accounts/10,
                                           accounts/50)))
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
        "total_accounts": accounts,
        "accounts": accounts,
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
    N = accounts
    for a, parameters in {
        'user_equals_password': (N/100, N/50),
        'lm_hash_count': (N/30, N/50),
        'cracked': (N/3, N/5),
        'nonunique': (N*.3, N*.1),
        'empty_password': (N/100, N/50),
    }.items():
        val = min(int(abs(random.gauss(*parameters))), N)
        result['report'][a] = [val, 100*val/N]

    return result


def test_stats(config_file, capsys):
    from hashcathelper.__main__ import main
    from hashcathelper.args import parse_config
    from hashcathelper.sql import get_session, Report, submit
    from hashcathelper.subcommands.db import get_stats

    config = parse_config(config_file)
    s = get_session(config.db_uri)
    random.seed(0)
    for i in range(100):
        data = create_report(random.randint(200, 200000), seed=i)
        submit(s, 'foo', 'wordlist', 'rule', '0.0', data)

    main([
        '--config',
        config_file,
        'db',
        'stats',
    ])
    capture = capsys.readouterr()
    print(capture.out)
    assert capture.out

    main([
        '--config',
        config_file,
        'db',
        'stats',
        '--format', 'json',
    ])
    capture = capsys.readouterr()
    print(capture.out)
    assert capture.out

    expected = {
        1: {'cracked': [13.0, 35.72, 18.48, 86], 'nonunique':
            [29.27, 29.22, 10.55, 54], 'user_equals_password':
            [0.35, 1.89, 1.41, 91], 'lm_hash_count': [4.07, 3.42,
                                                      1.84, 33],
            'empty_password': [1.35, 1.63, 1.25, 50],
            'largest_baseword_cluster': [11.88, 9.78, 1.93, 15],
            'average_password_length': [3.81, 8.58, 2.93, 93]},
        10: {'cracked': [56.95, 35.72, 18.48, 9], 'nonunique':
             [30.47, 29.22, 10.55, 43],
             'user_equals_password': [3.58, 1.89, 1.41, 9], 'lm_hash_count':
             [6.4, 3.42, 1.84, 6], 'empty_password': [1.65, 1.63, 1.25, 43],
             'largest_baseword_cluster': [8.11, 9.78, 1.93, 77],
             'average_password_length': [8.66, 8.58, 2.93, 52]},
        20: {'cracked': [19.87, 35.72, 18.48, 73], 'nonunique':
             [51.03, 29.22, 10.55, 1],
             'user_equals_password': [1.37, 1.89, 1.41, 60], 'lm_hash_count':
             [3.02, 3.42, 1.84, 53], 'empty_password': [0.72, 1.63, 1.25, 70],
             'largest_baseword_cluster': [8.44, 9.78, 1.93, 71],
             'average_password_length': [3.28, 8.58, 2.93, 95]},
    }

    s = get_session(config.db_uri)
    for i, val in expected.items():
        r = s.query(Report).filter_by(id=i).one()
        all_entries = s.query(Report).all()
        result = get_stats(r, all_entries)
        print(result)
        assert result == val
