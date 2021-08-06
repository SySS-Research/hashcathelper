import logging

log = logging.getLogger(__name__)


def pretty_print(report):
    from .analytics import labels
    out = ''
    simple_values = [
        [v, labels.get(k, k)] for k, v in report.items()
        if not (isinstance(v, (list, dict)))
    ]
    try:
        import tabulate
        out += tabulate.tabulate(simple_values) + "\n"
    except ImportError:
        log.error("Package 'tabulate' not installed")
        for val in simple_values:
            print("%s\t%s" % (val[0], val[1]))
    for k, v in report.items():
        if isinstance(v, dict):
            out += histogram(v, title=labels.get(k, k))
            out += "\n"
    return out


def histogram(dct, title='', width=50, indent=4):
    """Create a text-based horizontal bar chart using Unicode"""
    if not dct:
        return "%s: No data" % title
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
