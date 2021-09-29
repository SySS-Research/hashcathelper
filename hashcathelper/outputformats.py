import logging

log = logging.getLogger(__name__)

css = """
  <style>
    .chart .label {
      text-anchor: end;
      font-family: monospace;
    }
    .chart .number {
      text-anchor: begin;
      font-family: monospace;
    }
  </style>
"""

HEADER = dict(
    text="",
    html="""
<html><head><title>Hashcat Helper Report</title>%s</head><body>
    """ % css,
)

FOOTER = dict(
    text="",
    html="</body></html>",
)


def export(report, format):
    from hashcathelper.consts import labels
    table = []
    histograms = []
    # Iterate through the report. Dicts become histograms,
    # everything else becomes a table.
    for k, v in report.items():
        if isinstance(v, dict):
            title = labels.get(k, k)
            histograms.append(histogram(v, title, format))
        else:
            label = labels.get(k, k)
            value = v
            if (isinstance(value, (list, tuple)) and len(value) == 2):
                value = "%d (%.2f%%)" % tuple(value)
            else:
                value = str(value)
            table.append([value, label])

    out = HEADER[format]
    if table:
        out += format_table(table, format)
    if histograms:
        out += '\n'.join(histograms)

    out += FOOTER[format]

    return out


def format_table(tab, format):
    if format == 'text':
        return format_table_text(tab)
    elif format == 'html':
        return format_table_html(tab)


def histogram(dct, title, format):
    if format == 'text':
        return histogram_text(dct, title)
    elif format == 'html':
        return histogram_html(dct, title)


def format_table_text(tab):
    """Format a list of 2-tuples"""

    max_len = max(map(len, (x[0] for x in tab)))
    out = ''.join("%s%s%s\n" % (x[0], ' '*(max_len + 2 - len(x[0])), x[1])
                  for x in tab)
    return out


def histogram_text(dct, title='', width=50, indent=4):
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


def format_table_html(tab):
    out = "<h1>Key quantities</h1>"
    out += """
    <table><thead><tr><th>Quantity</th><th>Description</th></tr></thead><tbody>
    """
    row_template = "<tr><td>%s</td><td>%s</td></tr>"

    for row in tab:
        out += row_template % (row[0], row[1])

    out += "</tbody></table>"
    return out


def histogram_html(dct, title, width=500):
    out = "<h1>%s</h1>" % title
    out += """<svg class="chart" width="100%" height="120">"""
    bar_template = """
<g transform="translate(150,%(y)d)">
  <rect width="%(width)d" height="19" fill="red"></rect>
  <text class="label" x="%(labelpos)d" y="9.5" dy=".35em">%(text)s</text>
  <text class="number" x="%(numberpos)d" y="9.5" dy=".35em">%(number)s</text>
</g>
    """

    maxval = max(dct.values())
    y = 0
    for k, v in dct.items():
        if k == '':
            k = '&lt;BLANK&gt;'
        width_px = int(width * v/maxval)
        row = dict(
            text=k,
            width=width_px,
            y=y,
            labelpos=-2,
            numberpos=width_px+2,
            number=v,
        )
        out += (bar_template % row)
        y += 20

    out += "</svg>"
    return out
