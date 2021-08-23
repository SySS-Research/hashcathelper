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
    try:
        questions = ask_questions(config)
    except KeyboardInterrupt:
        log.info("CTRL-C caught, aborting...")
        return

    id_ = submit(
        session,
        questions['submitter_email'],
        questions['wordlist'],
        questions['rule_set'],
        questions['hashcat_version'],
        data,
    )

    log.info("Entry with ID %d submitted. Thanks for contributing!" % id_)


def ask_questions(config):
    import subprocess
    import os

    print("="*79)
    print(
        """You are about to submit a report from hashcathelper to the database.
Please make sure the data is of high quality and that inactive accounts have
been filtered."""
    )
    print("="*79)
    print('\n')
    print('Press CTRL-C to abort')
    print('\n')

    result = {}
    result['submitter_email'] = ask_question(
        "Please provide your e-mail address in case questions come up"
        " (optional)",
    )

    result['wordlist'] = ask_question(
        'The wordlist you used',
        default=os.path.basename(config.wordlist),
    )

    result['rule_set'] = ask_question(
        'The rule set you used',
        default=os.path.basename(config.rule),
    )

    try:
        hashcat_version = subprocess.check_output(
            [config.hashcat_bin, '-V']
        ).decode().strip()
    except Exception as e:
        log.error(str(e))
        hashcat_version = 'unknown'

    result['hashcat_version'] = ask_question(
        'The version of hashcat you used',
        default=hashcat_version,
    )

    return result


def ask_question(description, default=None, valid=None):
    # Import readline so we can use backspace in `input()`
    # It automatically wraps `input()`, nothing else needed
    import readline  # noqa
    print(description)

    while True:
        if default:
            prompt = '[%s] > ' % default
        else:
            prompt = '> '
        answer = input(prompt)
        if not answer:
            answer = default
        if valid and answer not in valid:
            print("Invalid answers. Allowed: %s" % valid)
        else:
            break

    return answer


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
        from tabulate import tabulate
        from hashcathelper.consts import labels
        data = [[labels.get(k, k) + ' (%)']+v for k, v in result.items()]

        # Remove percentage on average pw length
        data[-1][0] = data[-1][0][:-4]

        out = tabulate(
            data,
            headers=[
                "Key", "Value", "Mean", "Std. Dev.", "Perc.",
            ],
        )
    elif args.format == 'json':
        import json
        out = json.dumps(result, indent=2)

    out += '\n'
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
        s = sum(n < x for n in numbers)
    else:
        s = sum(n > x for n in numbers)
    result = s/len(numbers)*100
    return int(100*result)/100


def get_stats(entry, all_entries):
    from collections import OrderedDict
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
    higher_is_better = [
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
    result = OrderedDict()
    for q in relative_quantities+absolute_quantities:
        nums = [e[q] for e in all_entries]
        p = int(percentile(
            entry[q],
            nums,
            higher_is_better=(q in higher_is_better),
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
                int(100 * entry[q])/100,
                int(100 * mean(nums))/100,
                int(100 * stddev(nums))/100,
                p,
            ]

    return result
