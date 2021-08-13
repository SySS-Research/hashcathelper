"""
Test the `db` subcommand
"""

from collections import namedtuple
import os
import json


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
