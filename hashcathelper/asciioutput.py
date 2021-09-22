import logging

log = logging.getLogger(__name__)


def pretty_print(report):
    from hashcathelper.consts import labels
    out = []

    charts = ""
    # Iterate through the report. Dicts become histograms,
    # everything else becomes a table.
    for k, v in report.items():
        if isinstance(v, dict):
            charts += histogram(v, title=labels.get(k, k))
            charts += "\n"
        else:
            label = labels.get(k, k)
            value = v
            if (isinstance(value, (list, tuple)) and len(value) == 2):
                value = "%d (%.2f%%)" % tuple(value)
            else:
                value = str(value)
            out.append([value, label])

    if out:
        out = format_table(out)
    else:
        out = ''

    return out + charts


def format_table(tab):
    """Format a list of 2-tuples"""

    max_len = max(map(len, (x[0] for x in tab)))
    out = ''.join("%s%s%s\n" % (x[0], ' '*(max_len + 2 - len(x[0])), x[1])
                  for x in tab)
    return out


def histogram(dct, title='', width=50, indent=4):
    """Create a text-based horizontal bar chart using Unicode"""
    if not dct:
        return "%s: No data" % title
    maxval = max(dct.values())
    maxwidth = max([len(str(k)) for k in dct.keys()])
    blocks = [
        '',        # 0/8
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
            k = '<BLANK>'
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
