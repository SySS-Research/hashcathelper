import logging

from hashcathelper.args import subcommand, argument, parse_config

log = logging.getLogger(__name__)

args = []

args.append(argument(
    dest='hashfile',
    nargs='+',
    help="path to a file containing hashes in pwdump format",
))

args.append(argument(
    '-s', '--suffix',
    default='.out',
    type=str,
    help="results will be placed in the same directory as the input file "
         "with the same name, except a suffix will be appended plus a number "
         "if the file already exists (default: %(default)s)",
))

args.append(argument(
    '-L', '--skip-lm',
    default=False,
    action='store_true',
    help="Do not crack LM hashes first",
))


@subcommand(args)
def ntlm(args):
    '''Crack NTLM hashes from a SAM hive or NTDS.dit'''
    import shutil
    import tempfile

    from hashcathelper.hashcat import crack_pwdump

    config = parse_config(args.config)

    do_sanity_check(config)

    TEMP_DIR = tempfile.mkdtemp(
        prefix=args.hashfile[0]+'_hch_',
        dir='.',
    )
    log.info("Created temporary directory: %s" % TEMP_DIR)

    skip_lm = False
    if len(args.hashfile) == 1:
        log.info("Starting hashcat...")
        if args.skip_lm:
            skip_lm = True
        if not check_lm_hashes(args.hashfile[0]):
            log.info("No LM hashes found")
            skip_lm = True
        password_file = crack_pwdump(
            config.hashcat_bin,
            args.hashfile[0],
            TEMP_DIR,
            config.wordlist,
            config.rule,
            skip_lm=skip_lm,
        )
        result = copy_result(password_file, args.hashfile[0], args.suffix)
        log.info("Success! Output is in: %s" % result)
    else:
        log.info("Compiling files into one...")
        compiled_hashfile = compile_files(args.hashfile, TEMP_DIR)
        log.info("Starting hashcat...")
        if args.skip_lm:
            skip_lm = True
        if not check_lm_hashes(compiled_hashfile):
            log.info("No LM hashes found")
            skip_lm = True
        password_file = crack_pwdump(
            config.hashcat_bin,
            compiled_hashfile,
            TEMP_DIR,
            config.wordlist,
            config.rule,
            skip_lm=skip_lm,
        )
        log.info("Decompiling files...")
        result = decompile_file(password_file, args.hashfile, args.suffix)
        log.info("Success! Output is in: %s" % ', '.join(result))
    log.info("Deleting temporary directory...")
    shutil.rmtree(TEMP_DIR)
    log.info("Done.")


def do_sanity_check(config):
    import os
    if not config.hashcat_bin:
        log.critical("Config value not provided: %s" % 'hashcat_bin')
        exit(1)

    for path in [config.wordlist, config.rule, config.hashcat_bin]:
        if not os.path.isfile(path):
            log.critical("File not found: %s" % path)
            exit(1)


def compile_files(hashfiles, tempdir='.'):
    """Compile several files into one"""
    import tempfile
    result = tempfile.NamedTemporaryFile(
        dir=tempdir, delete=False, suffix='compiled'
    ).name

    with open(result, 'wb') as f_out:
        for hf in hashfiles:
            with open(hf, 'rb') as f_in:
                f_out.write(f_in.read())

    return result


def decompile_file(password_file, hashfiles, suffix):
    """Reverse the process based on the original hashfiles

    Returns the resulting filenames
    """
    from hashcathelper.utils import get_nthash

    # Create dict with original usernames and hashes and create file
    # descriptors
    usernames = {}
    hashes = {}
    filenames = []

    for hf in hashfiles:
        filename = find_filename(hf, suffix)
        filenames.append(filename)
        fp = open(filename, 'wb')
        with open(hf, 'rb') as f:
            hashes[fp] = set()
            usernames[fp] = set()
            for line in f.read().splitlines():
                username, _, _, nthash = line.split(b':')[:4]
                usernames[fp].add(username)
                hashes[fp].add(b':'.join([username, nthash]))

    # Iterate over cracked passwords and store in correct outfile
    with open(password_file, 'br') as f:
        for line in f.read().splitlines():
            username = line.split(b':')[0]
            # Find right file descriptor (usernames can be without UPN
            # suffix/domain, so mapping is not 1 to 1
            # Try username only first
            candidates = [fp for fp, names in usernames.items()
                          if username in names]
            if len(candidates) == 1:
                candidates[0].write(line + b'\n')
            else:
                #  Didn't get a unique result, so hash the password and try
                #  now to see which original file it was
                pw = b':'.join(line.split(b':')[1:])
                nthash = get_nthash(pw)
                candidates = [fp for fp, names in hashes.items()
                              if b':'.join([username, nthash]) in names]
                for fp in candidates:
                    fp.write(line + b'\n')
                if not candidates:
                    log.error(
                        "Orphaned user: %s:%s" % (
                            username.decode(errors='replace'),
                            nthash,
                        )
                    )

    # Close files
    for fp in hashes.keys():
        fp.close()

    return filenames


def copy_result(src, dest, suffix):
    """Copy result to file with correct suffix while making sure not to
    overwrite files

    Returns the new filename
    """
    import shutil

    target = find_filename(dest, suffix)
    shutil.copy(src, target)
    return target


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


def check_lm_hashes(filename):
    """Returns True iff the file contains at least one file that contains a
    non-empty LM hash"""
    from hashcathelper.consts import LM_EMPTY

    with open(filename, 'r') as f:
        for line in f.readlines():
            if line.split(':')[2] != LM_EMPTY:
                return True
    return False
