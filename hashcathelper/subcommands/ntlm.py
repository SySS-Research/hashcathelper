import logging

from ..args import subcommand, argument, parse_config

log = logging.getLogger(__name__)

args = []

args.append(argument(
    dest='hashfile',
    help="path to the file containing the hashes",
))

args.append(argument(
    '-o', '--outfile',
    default='',
    type=str,
    help="path to the resulting output file (default: <hashfile>.out)",
))


@subcommand(args)
def ntlm(args):
    '''Crack NTLM hashes from a SAM hive or NTDS.dit'''
    import shutil
    import tempfile

    from ..hashcat import crack_pwdump

    config = parse_config(args.config)
    TEMP_DIR = tempfile.TemporaryDirectory(
        prefix=args.hashfile+'_hch_',
        dir='.',
    )
    password_file = crack_pwdump(
        config.hashcat_bin,
        args.hashfile,
        TEMP_DIR.name,
        config.wordlist,
        config.rule,
    )
    shutil.copy(password_file, args.outfile or args.hashfile + '.out')
