import logging

from ..args import subcommand, argument, parse_config

log = logging.getLogger(__name__)

args = []

args.append(argument(
    dest='hashfile',
    nargs='+',
    help="path to the file containing the hashes",
))

args.append(argument(
    '-s', '--suffix',
    default='.out',
    type=str,
    help="results will be placed in the same directory as the input file "
         "with the same name, except a suffix will be appended plus a number "
         "if the file already exists (default: %(default)s)",
))


@subcommand(args)
def ntlm(args):
    '''Crack NTLM hashes from a SAM hive or NTDS.dit'''
    import tempfile

    from ..hashcat import crack_pwdump

    config = parse_config(args.config)
    TEMP_DIR = tempfile.TemporaryDirectory(
        prefix=args.hashfile[0]+'_hch_',
        dir='.',
    )

    if len(args.hashfile) == 1:
        password_file = crack_pwdump(
            config.hashcat_bin,
            args.hashfile[0],
            TEMP_DIR.name,
            config.wordlist,
            config.rule,
        )
        copy_result(password_file, args.hashfile, args.suffix)
    else:
        compiled_hashfile = compile_files(args.hashfile, TEMP_DIR.name)
        password_file = crack_pwdump(
            config.hashcat_bin,
            compiled_hashfile,
            TEMP_DIR.name,
            config.wordlist,
            config.rule,
        )
        decompile_file(password_file, args.hashfile, args.suffix)


def compile_files(hashfiles, tempdir='.'):
    """Compile several files into one"""
    import tempfile
    result = tempfile.NamedTemporaryFile(dir=tempdir, delete=False).name

    with open(result, 'w') as f_out:
        for hf in hashfiles:
            with open(hf, 'r') as f_in:
                f_out.write(f_in.read())

    return result


def decompile_file(password_file, hashfiles, suffix):
    """Reverse the process based on the original hashfiles"""

    # Create dict with original hashes and create file descriptors
    hashes = {}
    for hf in hashfiles:
        fp = open(find_filename(hf, suffix), 'w')
        with open(hf, 'r') as f:
            hashes[fp] = set(line.split(':')[0]
                             for line in f.read().splitlines())

    # Iterate over cracked passwords and store in correct outfile
    with open(password_file, 'r') as f:
        for line in f.read().splitlines():
            user = line.split(':')[0]
            for fp, names in hashes.items():
                if user in names:
                    fp.write(line + '\n')

    # Close files
    for fp in hashes.keys():
        fp.close()


def copy_result(src, dest, suffix):
    """Copy result to file with correct suffix while making sure not to
    overwrite files"""
    import shutil

    target = find_filename(dest, suffix)
    shutil.copy(src, target)


def find_filename(filename, suffix):
    """Find file with correct suffix that doesn't exist"""
    import os
    import tempfile
    target = filename + suffix

    base = target
    count = 0
    while os.path.exists(target):
        count += 1
        target = "%s.%03d" % (base, count)
        if count > 1000:
            target = tempfile.NamedTemporaryFile(delete=False).name
            log.error((
                "Couldn't find a free filename for %s, "
                "using temporary file: %s"
            ) % (filename, target))
            break

    return target
