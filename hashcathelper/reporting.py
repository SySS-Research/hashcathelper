import logging
import json
from collections import OrderedDict

try:
    from html import escape as htmlescape
except ImportError:
    from cgi import escape as htmlescape

from hashcathelper.consts import labels

log = logging.getLogger(__name__)


class ElementEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return obj.as_json()
        except AttributeError:
            return json.JSONEncoder.default(self, obj)


class Element(object):
    def __init__(self, label, title=None,
                 formats=['json', 'html', 'text']):
        self._label = label
        if title:
            self._title = title
        else:
            self._title = labels.get(label, label)
        self._formats = formats

    def export(self, format):
        assert format in ['html', 'text', 'json']
        if format not in self._formats:
            return ""
        if self.is_empty():
            return ""
        f = getattr(self, '_export_%s' % format)
        return f()

    def _export_json(self):
        return json.dumps(self, cls=ElementEncoder, indent=2)

    def json(self):
        return json.loads(json.dumps(self, cls=ElementEncoder))

    def is_empty(self):
        return False


class RelativeQuantity(object):
    def __init__(self, numerator, denominator=100):
        if denominator == 0:
            raise Exception("Denominator can't be zero")
        self.numerator = numerator
        self.denominator = denominator

    def __int__(self):
        return self.numerator

    def __str__(self):
        percentage = int(self.numerator/self.denominator * 100 * 100)/100
        result = "%s (%d%%)" % (self.numerator, percentage)
        return result

    def as_json(self):
        return [self.numerator, self.denominator]


class Section(Element):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._level = 1
        self._elements = OrderedDict()

    def __add__(self, element):
        if isinstance(element, Section):
            element._level = self._level + 1
        self._elements[element._label] = element
        return self

    def _export_html(self):
        result = "<h%(level)s>%(title)s</h%(level)d>" % dict(
            title=self._title,
            level=self._level,
        )
        for e in self._elements.values():
            result += e.export('html')
        return result

    def _export_text(self):
        chars = "=-~.\"'"
        result = "%s\n%s\n\n" % (
            self._title,
            chars[self._level] * len(self._title),
        )
        for e in self._elements.values():
            result += e.export('text')
        return result

    def as_json(self):
        return self._elements

    def is_empty(self):
        return len(self._elements) == 0


class Report(Section):
    CSS = """
      <style>
        body {
          font-family: Helvetica, Arial, Sans-Serif;
        }
        .chart .label {
          text-anchor: end;
          font-family: monospace;
        }
        .chart .number {
          text-anchor: begin;
          font-family: monospace;
        }
        .card-collection {
            display: flex;
            flex-wrap: wrap;
            padding: 0 2em 0 2em;
            align-items: stretch;
        }
        .card {
            flex: 0 1 200px;
            height: 15em;
            box-sizing: border-box;
            margin: 1rem .25em;
            border: 1px solid;
            border-color: lightgray;
            align-content: center;
        }
        .card-label {
            text-align: center;
            padding: .25em;
        }
        .card-quantity {
            height: 10em;
            display: flex;
            justify-content: center;
            align-items: center;
            text-anchor: middle;
            dominant-baseline: middle;
        }
        .pure-number {
            display: table-cell;
            vertical-align: middle;
            font-size: 48pt;
            padding: .25em;
        }
        .chart-text {
            font-size: 12;
            transform: translateY(0.1em);
        }
        .donut {
            height: 100%;
        }
        .donut-segment {
            stroke: #e28743;
       }
       table, ul {
            font-family: monospace;
       }
      </style>
    """

    HEADER = """
    <html><head><title>Hashcat Helper Report</title>%s</head><body>
        """ % CSS

    FOOTER = "</body></html>"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._level = 0

    def _export_html(self):
        result = self.HEADER
        for e in self._elements.values():
            result += e.export('html')
        result += self.FOOTER
        return result

    def _export_text(self):
        rule = '='*(len(self._title) + 1)
        result = "%s\n%s\n%s\n\n" % (
            rule, self._title, rule
        )
        for e in self._elements.values():
            result += e.export('text')
        return result


class List(list, Element):
    def __init__(self, label, data, *args, **kwargs):
        list.__init__(self)
        Element.__init__(self, label, *args, **kwargs)
        self.extend(data)

    def _export_html(self):
        result = "<b>%s</b><br/><ul>" % htmlescape(self._title)
        for i in self:
            result += "<li>%s</li>" % i
        result += "</ul>"
        return result

    def _export_text(self):
        out = self._title + "\n"
        out += "\n".join(["   * %s" % x for x in self])
        out += "\n\n"
        return out

    def as_json(self):
        return self

    def is_empty(self):
        return len(self) == 0


class Table(OrderedDict, Element):
    headers = ["Description", "Value"]

    def __init__(self, label, data, *args, **kwargs):
        OrderedDict.__init__(self)
        Element.__init__(self, label, *args, **kwargs)
        self.update(data)

    def _html_card(self, label, value):
        """Return a card with a value

        value can be int or `RelativeQuantity`
        """

        donut_section = """
<svg viewBox="0 0 42 42" class="donut">
  <circle class="donut-hole" cx="21" cy="21" r="15.91549430918954" fill="#fff"></circle>
  <circle class="donut-ring" cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="#d2d3d4" stroke-width="3"></circle>
  <circle class="donut-segment" cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke-width="3"
  stroke-dasharray="%(percent)d %(remaining)d" stroke-dashoffset="25"></circle>
  <g class="chart-text">
      <text x="50%%" y="50%%" class="donut-number">
          %(center)s
      </text>
  </g>
</svg>
"""
        if isinstance(value, RelativeQuantity):
            # RelativeQuantity, draw a donut section
            percent = int(value.numerator/value.denominator*100)
            inner = donut_section % dict(
                percent=percent,
                remaining=100-percent,
                center="%s%%" % percent,
            )
            quantity = '<div class="card-quantity">%s</div>' % inner
        else:
            quantity = '<div class="card-quantity"><div class="pure-number">%s</div></div>' % value

        label = labels.get(label, label)
        label = '<div class="card-label">%s</div>' % label
        result = '<div class="card">%s%s</div>' % (quantity, label)

        return result

    def _export_html(self):
        if not self:
            return ""
        cards = [self._html_card(k, v) for k, v in self.items()]
        result = '<div class="card-collection">%s</div>' % '\n'.join(cards)
        return result

    def _export_text(self):
        if not self:
            return ""
        data = OrderedDict(
            (str(labels.get(label, label)), value)
            for label, value in self.items()
        )
        max_len = max(len(x) for x in data)
        out = self._title + "\n"
        rows = [
            "    %s%s%s\n" % (label, ' '*(max_len+2-len(label)), value)
            for label, value in data.items()
        ]
        out += ''.join(rows)
        return out + "\n"

    def as_json(self):
        return self

    def is_empty(self):
        return len(self) == 0


class LongTable(Table):
    headers = []

    def _export_html(self):
        result = '<table>'
        for k, v in self.items():
            v = htmlescape(", ".join(v))
            result += '<tr><td>%s</td><td>%s</td></tr>' % (k, v)
        result += '</table>'
        return result

    def _export_text(self):
        old = {k: v for k, v in self.items()}
        new = {k: ", ".join(v) for k, v in self.items()}
        self.clear()
        self.update(new)
        try:
            return super()._export_text()
        finally:
            self.clear()
            self.update(old)


class Histogram(Element):
    html_width = 500
    text_width = 50
    text_indent = 4

    def __init__(self, data, *args, **kwargs):
        assert isinstance(data, dict)
        super().__init__(*args, **kwargs)
        self._data = data

    def _export_html(self):
        if not self._data:
            return ""
        out = """
<svg role="img" aria-label="[%(title)s]" class="chart"
width="100%%" height="120">
<title>%(title)s</title>""" % dict(title=htmlescape(self._title))
        bar_template = """
<g transform="translate(150,%(y)d)">
  <rect width="%(width)d" height="19" fill="#e28743"></rect>
  <text class="label" x="%(labelpos)d" y="9.5" dy=".35em">%(text)s</text>
  <text class="number" x="%(numberpos)d" y="9.5" dy=".35em">%(number)s</text>
</g>
        """

        maxval = max(self._data.values())
        y = 0
        for k, v in self._data.items():
            if k == '':
                k = '<BLANK>'
            width_px = int(self.html_width * v/maxval)
            row = dict(
                text=htmlescape(str(k)),
                width=width_px,
                y=y,
                labelpos=-2,
                numberpos=width_px+2,
                number=v,
            )
            out += (bar_template % row)
            y += 20

        out += "</svg>"
        out = "<figure>" + (
            "<figcaption><b>%s</b></figcaption>" % htmlescape(self._title)
        ) + out + "</figure>"
        return out

    def _export_text(self):
        """Create a text-based horizontal bar chart using Unicode"""
        if not self._data:
            return "%s: No data\n\n" % self._title
        maxval = max(self._data.values())
        maxwidth = max([len(str(k)) for k in self._data.keys()])
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
        if self._title:
            result += self._title + '\n'
        for k, v in self._data.items():
            if k == '':
                k = '<BLANK>'
            line = ' '*self.text_indent
            line += ' '*(maxwidth - len(str(k))) + str(k) + ' '
            length = v/maxval * self.text_width
            rounded = int(length)
            remainder = int(round((length - rounded) * 8))
            line += blocks[-1]*rounded + blocks[remainder]
            if isinstance(v, int):
                line += ' %d' % v
            result += line + '\n'

        return result + "\n"

    def as_json(self):
        return OrderedDict(self._data)

    def is_empty(self):
        return len(self._data) == 0
