import argparse
import logging
import os
import subprocess

from ..args import subcommand, argument, subparsers_map, parse_config

log = logging.getLogger(__name__)
args = []

args.append(argument(
    '--db-uri',
    default=None,
    help="database URI (default: use value from config)",
))


@subcommand(args)
def db(args):
    '''Interact with the database'''


subparsers = subparsers_map['db'].add_subparsers(help='choose an action')


args_submit = []

args_submit.append(argument(
    dest='infile',
    type=argparse.FileType('r'),
    help="path to an input file",
))


@subcommand(args_submit, parent=subparsers)
def submit(args):
    '''Submit a result to the database'''
    import json

    from ..sql import submit

    session = get_session(args)
    data = json.load(args.infile)

    config = parse_config(args.config)
    questions = ask_questions(config)

    id_ = submit(
        session,
        questions.submitter_email,
        questions.wordlist,
        questions.rule_set,
        questions.hashcat_version,
        data,
    )

    log.info("Entry with ID %d submitted. Thanks for contributing!" % id_)


def ask_questions(config):
    import pypsi.wizard as wiz
    import pypsi.shell

    steps = []

    steps.append(wiz.WizardStep(
        'submitter_email',
        'Your e-mail just in case',
        "Please provide your e-mail address in case questions come up"
        " (optional)",
    ))

    steps.append(wiz.WizardStep(
        'wordlist',
        'The wordlist you used',
        "Just the name of the wordlist in case you didn't use the default"
        " wordlist that is configured on this system",
        default=os.path.basename(config.wordlist),
    ))

    steps.append(wiz.WizardStep(
        'rule_set',
        'The wordlist you used',
        "Just the name of the rule set in case you didn't use the default"
        " rule set that is configured on this system",
        default=os.path.basename(config.rule),
    ))

    try:
        hashcat_version = subprocess.check_output(
            [config.hashcat_bin, '-V']
        ).decode().strip()
    except FileNotFoundError:
        hashcat_version = 'unknown'
    steps.append(wiz.WizardStep(
        'hashcat_version',
        'The version of hashcat you used',
        "Version of hashcat you used for cracking in case you used another"
        " system",
        default=hashcat_version,
    ))

    prompt = wiz.PromptWizard(
        'Hashcathelper Submit',
        """You are about to submit a report from hashcathelper to the database.
Please make sure the data is of high quality and that inactive account have
been filtered.""",
        steps=steps,
    )

    result = prompt.run(
        pypsi.shell.Shell()
    )
    return result


args_query = []

args_query.append(argument(
    dest='id',
    nargs='?',
    help="show details of the entry with this ID; leave empty to list all"
         " entries",
))

args_query.append(argument(
    '-o', '--outfile',
    default=None,
    help="path to an output file (default: stdout)",
))


@subcommand(args_query, parent=subparsers)
def query(args):
    '''List all entries'''
    from ..sql import Report

    s = get_session(args)
    out = []
    for r in s.query(Report).order_by(Report.id.asc()).all():
        out.append([r.id, r.submission_date, r.submitter_email])

    for o in out:
        print("%s\t%s\t%s" % tuple(o))


args_stats = []

args_stats.append(argument(
    '-o', '--outfile',
    default=None,
    help="path to an output file (default: stdout)",
))

args_stats.append(argument(
    '-f', '--format',
    choices=['text', 'json'],
    default='text',
    help="output format (default: %(default)s)",
))

args_stats.append(argument(
    dest='id',
    default=None,
    nargs='?',
    help="show stats of the entry with this ID; leave empty for last entry",
))


@subcommand(args_stats, parent=subparsers)
def stats(args):
    '''Show statistics for one database entry'''
    from ..sql import Report

    s = get_session(args)
    if args.id:
        r = s.query(Report).filter_by(id=args.id).one()
    else:
        r = s.query(Report).order_by(Report.id.desc()).first()
    all_entries = s.query(Report).all()

    result = get_stats(r, all_entries)

    print(result)

    #  out_single = [[col.name, getattr(r, col.name)]
    #                for col in r.__table__.columns]
    #  if args.format == 'text':
    #      from ..asciioutput import format_table
    #      out_single = format_table(out_single)
    #      print(out_single)


def get_session(args):
    from ..sql import get_session
    config = parse_config(args.config)
    if not args.db_uri:
        args.db_uri = config.db_uri
    session = get_session(args.db_uri)
    return session


def get_stats(entry, all_entries):
    relative_quantities = [
        'cracked',
        'unique',
        'user_equals_password',
        'non_empty_lm_hash',
        'empty_password',
        'largest_baseword_cluster',
    ]
    absolute_quantities = [
        'avg_pwd_length',
    ]

    # TODO <-- continue here
