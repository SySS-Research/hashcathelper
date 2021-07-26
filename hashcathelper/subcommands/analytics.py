from ..args import subcommand, argument

args = []

args.append(argument(
    '-H', '--hashes',
    default=None,
    help="path to a file containing hashes. Format: "
         "'<UPN suffix>\\<account name>:<id>:<lm hash>:<nt hash>:::'",
))

args.append(argument(
    '-A', '--accounts-plus-passwords',
    default=None,
    help="path to a file with the results from the `ntlm` subcommand. "
         "Format: '<account name>:<password>'",
))

args.append(argument(
    '-P', '--passwords-only',
    default=None,
    help="path to a file with only passwords; one per line",
))

args.append(argument(
    '-F', '--filter-accounts',
    default=None,
    help="""
path to a file containing names of accounts which are subject to analysis,
all other accounts will be filtered out (Example: only active accounts,
only kerberoastable accounts, etc.). If empty, all accounts will be
subject to analysis. Format: one per line, without domain or UPN suffix,
case insensitive.
"""
))

args.append(argument(
    '-c', '--censor',
    action='store_true',
    default=False,
    help="only output statistics without sensitive information "
         "(default: %(default)s)",
))

args.append(argument(
    '-f', '--format',
    choices=['text', 'json'],
    default='text',
    help="output format (default: %(default)s)",
))

args.append(argument(
    '-o', '--outfile',
    default=None,
    help="path to an output file (default: stdout)",
))


@subcommand(args)
def analytics(args):
    '''Output interesting statistics'''
    from ..analytics import create_report, labels
    report = create_report(
        args.hashes,
        args.accounts_plus_passwords,
        args.passwords_only,
        args.filter_accounts,
        censor=args.censor,
    )
    if not report:
        exit(1)

    if args.format == 'json':
        import json
        out = json.dumps(report, indent=4)
    elif args.format == 'text':
        out = ""
        simple_values = [
            [v, labels.get(k, k)] for k, v in report.items()
            if not (isinstance(v, (list, dict)))
        ]
        try:
            import tabulate
            out += tabulate.tabulate(simple_values) + "\n"
        except ImportError:
            import sys
            print("Error: package 'tabulate' not installed", file=sys.stderr)
            for val in simple_values:
                print("%s\t%s" % (val[0], val[1]))
        for k, v in report.items():
            if isinstance(v, dict):
                out += histogram(v, title=labels.get(k, k))
                out += "\n"

    if args.outfile:
        with open(args.outfile, 'w') as f:
            f.write(out)
    else:
        print(out, end='')


def histogram(dct, title='', width=50, indent=4):
    """Create a text-based horizontal bar chart using Unicode"""
    maxval = max(dct.values())
    maxwidth = max([len(str(k)) for k in dct.keys()])
    blocks = [
        '',
        '\u258F',  # 1/8
        '\u258E',  # 2/8
        '\u258D',  # 3/8
        '\u258C',  # 4/8
        '\u258B',  # 5/8
        '\u258A',  # 6/8
        '\u2589',  # 7/8
        '\u2588',  # 8/8
    ]

    result = ""
    if title:
        result += title + '\n'
    for k, v in dct.items():
        if k == '':
            k = '<EMPTY>'
        line = ' '*indent
        line += ' '*(maxwidth - len(str(k))) + str(k) + ' '
        length = v/maxval * width
        rounded = int(length)
        remainder = int(round((length - rounded) * 8))
        line += blocks[-1]*rounded + blocks[remainder]
        if isinstance(v, int):
            line += ' %d' % v
        result += line + '\n'

    return result
