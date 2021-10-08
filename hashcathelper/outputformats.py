import logging
import json
from collections import OrderedDict

from hashcathelper.consts import labels

from tabulate import tabulate

log = logging.getLogger(__name__)


class ElementEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return obj.as_json()
        except AttributeError:
            return json.JSONEncoder.default(self, obj)


class Element(object):
    def __init__(self, label, title=None):
        self._label = label
        if title:
            self._title = title
        else:
            self._title = labels.get(label, label)

    def export(self, format):
        assert format in ['html', 'text', 'json']
        f = getattr(self, '_export_%s' % format)
        return f()

    def _export_json(self):
        return json.dumps(self, cls=ElementEncoder, indent=2)


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
        self._elements = {}

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


class Report(Section):
    CSS = """
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
        list.__init__(self, *args, **kwargs)
        Element.__init__(self, label)
        self.extend(data)

    def _export_html(self):
        result = "<ul>"
        for i in self:
            result += "<li>%s</li>" % i
            result += "</ul>"
        return result

    def _export_text(self):
        return "\n".join([" * %s" % x for x in self])

    def as_json(self):
        return self


class Table(OrderedDict, Element):
    def __init__(self, label, data, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        Element.__init__(self, label)
        self.update(data)

    def _export_html(self):
        if not self:
            return ""
        data = [[labels.get(k, k), str(v)] for k, v in self.items()]
        result = tabulate(
            data,
            headers=["Value", "Description"],
            tablefmt='html',
        )
        return result

    def _export_text(self):
        if not self:
            return ""
        data = {labels.get(label, label): value
                for label, value in self.items()}
        max_len = max(map(len, (x for x in data)))
        out = self._title + "\n"
        out += ''.join("    %s%s%s\n" %
                       (label, ' '*(max_len+2-len(label)), value)
                       for label, value in data.items())
        return out + "\n"

    def as_json(self):
        return self


class LongTable(Table):
    pass


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
        out = "<h1>%s</h1>" % self._title
        out += """<svg class="chart" width="100%" height="120">"""
        bar_template = """
<g transform="translate(150,%(y)d)">
  <rect width="%(width)d" height="19" fill="red"></rect>
  <text class="label" x="%(labelpos)d" y="9.5" dy=".35em">%(text)s</text>
  <text class="number" x="%(numberpos)d" y="9.5" dy=".35em">%(number)s</text>
</g>
        """

        maxval = max(self._data.values())
        y = 0
        for k, v in self._data.items():
            if k == '':
                k = '&lt;BLANK&gt;'
            width_px = int(self.html_width * v/maxval)
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
