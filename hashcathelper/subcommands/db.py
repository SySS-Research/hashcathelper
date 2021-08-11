import argparse

from ..args import subcommand, argument, subparsers_map, parse_config

args = []

args.append(argument(
    '--db-uri',
    default=None,
    help="database URI (default: use value from config)",
))


@subcommand(args)
def db(args):
    '''Interact with the database'''
    config = parse_config(args.config)
    if not args.db_uri:
        args.db_uri = config.db_uri


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
    '''Query the database'''
    from ..sql import get_session
    get_session('sqlite:////tmp/test.sqlite')


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

args_query.append(argument(
    dest='id',
    default=None,
    nargs='?',
    help="show stats of the entry with this ID; leave empty for last entry",
))


@subcommand(args_stats, parent=subparsers)
def stats(args):
    '''Show statistics for one database entry'''
