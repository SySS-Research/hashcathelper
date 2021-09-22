import logging

log = logging.getLogger(__name__)

css = """
  <style>
    .chart text {
      text-anchor: end;
      font-family: monospace;
    }
  </style>
"""


def html_print(report):
    from hashcathelper.consts import labels
    out = []

    histograms = []
    table = []
    # Iterate through the report. Dicts become histograms,
    # everything else becomes a table.
    for k, v in report.items():
        if isinstance(v, dict):
            title = labels.get(k, k)
            histograms.append(histogram(v, title))
        else:
            label = labels.get(k, k)
            value = v
            if (isinstance(value, (list, tuple)) and len(value) == 2):
                value = "%d (%.2f%%)" % tuple(value)
            else:
                value = str(value)
            table.append([value, label])

    out = """
    <html><head><title>Hashcat Helper Report</title>%s</head><body>
    """ % css

    # Insert table
    out += "<h1>Key quantities</h1>"
    out += """
    <table><thead><tr><th>Quantity</th><th>Description</th></tr></thead><tbody>
    """
    row_template = "<tr><td>%s</td><td>%s</td></tr>"

    for row in table:
        out += row_template % (row[0], row[1])

    out += "</tbody></table>"

    # Insert histograms
    for svg in histograms:
        out += svg

    out += "</body></html>"

    return out


def histogram(dct, title, width=500):
    out = "<h1>%s</h1>" % title
    out += """<svg class="chart" width="100%" height="120">"""
    bar_template = """
    <g transform="translate(150,%(y)d)">
      <rect width="%(width)d" height="19" fill="red"></rect>
      <text x="%(pos)d" y="9.5" dy=".35em">%(text)s</text>
    </g>
    """

    maxval = max(dct.values())
    y = 0
    for k, v in dct.items():
        if k == '':
            k = '&lt;BLANK&gt;'
        row = dict(
            text=k,
            width=int(width * v/maxval),
            y=y,
            pos=0,
        )
        out += (bar_template % row)
        y += 20

    out += "</svg>"
    return out
