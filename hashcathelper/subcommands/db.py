import argparse
import logging

from hashcathelper.args import subcommand, argument, subparsers_map, \
        parse_config

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

    from hashcathelper.sql import submit

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
    import subprocess
    import os

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
    from hashcathelper.sql import Report

    s = get_session(args)
    out = []
    for r in s.query(Report).order_by(Report.id.asc()).all():
        out.append([r.id, r.submission_date, r.submitter_email,
                    r.accounts])

    for o in out:
        print('\t'.join(["%s"] * len(o)) % tuple(o))


args_stats = []

args_stats.append(argument(
    '-o', '--outfile',
    type=argparse.FileType(mode='w'),
    default='-',
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
    from hashcathelper.sql import Report

    s = get_session(args)
    if args.id:
        r = s.query(Report).filter_by(id=args.id).one()
    else:
        r = s.query(Report).order_by(Report.id.desc()).first()
    all_entries = s.query(Report).all()

    result = get_stats(r, all_entries)

    if args.format == 'text':
        from ..asciioutput import format_table
        out = format_table(result)

    args.outfile.write(out)


def get_session(args):
    from hashcathelper.sql import get_session
    config = parse_config(args.config)
    if not args.db_uri:
        args.db_uri = config.db_uri
    session = get_session(args.db_uri)
    return session


def normalize(entry, attr):
    return getattr(entry, attr)/entry.accounts


def mean(numbers):
    return float(sum(numbers)) / max(len(numbers), 1)


def stddev(numbers):
    mu = mean(numbers)
    variance = sum([((x - mu) ** 2) for x in numbers]) / len(numbers)
    stddev = variance ** 0.5
    return stddev


def percentile(x, numbers, higher_is_better=False):
    if higher_is_better:
        s = sum(n > x for n in numbers)
    else:
        s = sum(n < x for n in numbers)
    result = s/len(numbers)*100
    return int(100*result)/100


def get_stats(entry, all_entries):
    from hashcathelper.utils import prcnt

    relative_quantities = [
        'cracked',
        'nonunique',
        'user_equals_password',
        'lm_hash_count',
        'empty_password',
        'largest_baseword_cluster',
    ]
    absolute_quantities = [
        'average_password_length',
    ]

    # Copy ORMs to dicts
    entry_ = {}
    for q in relative_quantities:
        entry_[q] = normalize(entry, q)
    for q in absolute_quantities:
        entry_[q] = getattr(entry, q)
    all_entries_ = []
    for e in all_entries:
        e_ = {}
        for q in relative_quantities:
            e_[q] = normalize(e, q)
        for q in absolute_quantities:
            e_[q] = getattr(e, q)
        all_entries_.append(e_)
    entry = entry_
    all_entries = all_entries_

    # Compute the stats
    result = {}
    for q in relative_quantities+absolute_quantities:
        nums = [e[q] for e in all_entries]
        p = int(percentile(
            entry[q],
            nums,
        ))
        if q in relative_quantities:
            result[q] = [
                prcnt(entry[q], 1),
                prcnt(mean(nums), 1),
                prcnt(stddev(nums), 1),
                p,
            ]
        else:
            result[q] = [
                entry[q],
                mean(nums),
                stddev(nums),
                p,
            ]

    return result
