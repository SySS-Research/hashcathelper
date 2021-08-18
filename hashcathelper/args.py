import argparse
import pkgutil
from importlib import import_module
import logging

from hashcathelper._meta import __version__, __doc__

log = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    description=__doc__,
)

parser.add_argument(
    '-v', '--version', action='version',
    version='hashcathelper %s' % __version__,
)

parser.add_argument(
    '-c', '--config',
    type=str,
    help="path to config file; if empty we will try ./hashcathelper.conf"
    " and ${XDG_CONFIG_HOME:-$HOME/.config}/hashcathelper/hashcathelper.conf"
    " in that order",
)

parser.add_argument(
    '-l', '--log-level',
    choices=['INFO', 'WARNING', 'ERROR', 'DEBUG'],
    default='INFO',
    help="log level (default: %(default)s)",
)


subparsers = parser.add_subparsers(help='choose a sub-command',
                                   dest='subcommand')
# Keep track of the subparsers we add so we can add subsubparsers
subparsers_map = {}


def argument(*name_or_flags, **kwargs):
    """Convenience function to properly format arguments to pass to the
    subcommand decorator.
    """
    return (list(name_or_flags), kwargs)


def subcommand(args=[], parent=subparsers):
    """Decorator to define a new subcommand in a sanity-preserving way.
    The function will be stored in the ``func`` variable when the parser
    parses arguments so that it can be called directly like so::
        args = cli.parse_args()
        args.func(args)
    Usage example::
        @subcommand([argument("-d", help="Enable debug mode",
                              action="store_true")])
        def subcommand(args):
            print(args)
    Then on the command line::
        $ python cli.py subcommand -d
    """
    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
        subparsers_map[func.__name__] = parser
    return decorator


def parse_args(argv=None):
    from hashcathelper import subcommands
    for importer, modname, _ in pkgutil.iter_modules(subcommands.__path__):
        import_module('..subcommands.' + modname, __name__)
    args = parser.parse_args(argv)
    if not args.subcommand:
        parser.print_help()
        exit(0)
    return args


def parse_config(path):
    import configparser
    import collections
    import os

    import xdg.BaseDirectory

    config_parser = configparser.ConfigParser()
    if not path:
        path = './hashcathelper.conf'
        if not os.path.exists(path):
            path = os.path.join(
                xdg.BaseDirectory.xdg_config_home,
                'hashcathelper',
                'hashcathelper.conf',
            )
    config_parser.read(path)
    attrs = 'rule wordlist hashcat_bin hash_speed db_uri'.split()
    for a in attrs:
        if a not in config_parser['DEFAULT']:
            log.error('Attribute undefined: ' + a)
    Config = collections.namedtuple('Config', attrs)
    config = Config(
        *[config_parser['DEFAULT'].get(a) for a in attrs]
    )

    return config
