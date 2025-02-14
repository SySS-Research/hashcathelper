import os
import re
import binascii


def prcnt(a, b=None):
    """Return percentage rounded to two decimals"""
    if b:
        return int(a / b * 100 * 100) / 100
    else:
        return int(a * 100) / 100


def get_nthash(password):
    """Compute NT hash of password (must be bytes)"""
    from hashcathelper import md4

    password = password.decode(errors="ignore").encode("utf-16le")
    result = md4.MD4(password)
    result = result.hexdigest()
    return result


USER_REGEX = r"^((?P<upn_suffix>[A-Za-z0-9_\.-]+)\\)?(?P<username>[^:]+)"
USER_PATTERN = re.compile(USER_REGEX + "$")
USER_PATTERN_SUFFIX = re.compile(
    r"^(?P<username>[^@]+)@(?P<upn_suffix>[A-Za-z0-9_\.-]+)$"
)
USER_PASS_PATTERN = re.compile(USER_REGEX + r":(?P<password>.*)$")
PWDUMP_PATTERN = re.compile(
    USER_REGEX + r":(?P<id>[0-9]*):(?P<lmhash>[a-f0-9]{32}):(?P<nthash>[a-f0-9]{32})"
    r":::(?P<comment>.*)$"
)
HEX_PATTERN = re.compile(r"^\$HEX\[(?P<hexascii>[a-f0-9]+)\]$")


class User(object):
    attributes = "username upn_suffix id lmhash nthash password comment".split()

    def __init__(self, line):
        self.line = line
        # Try to pass one pattern after another
        for p in [
            PWDUMP_PATTERN,
            USER_PASS_PATTERN,
            USER_PATTERN_SUFFIX,
            USER_PATTERN,
        ]:
            m = p.search(line)
            if m:
                break
        if not m:
            raise ValueError("Could not parse line: %s" % line)

        for a in self.attributes:
            try:
                val = m.group(a)
                if val:
                    val = val.strip()
                setattr(self, a, val)
            except IndexError:
                # "no such group"
                setattr(self, a, None)

        if not self.username:
            raise ValueError("Could not parse line: %s" % line)

        # Set full_username; won't really be used though
        if self.upn_suffix:
            self.full_username = "%s\\%s" % (
                self.upn_suffix,
                self.username,
            )
        else:
            self.full_username = self.username

        # Let's also try to convert HEX passwords.
        # Hashcat appears to insert spurious non-printable characters
        # sometimes. Passwords must be printable so doing the following will
        # probably lead to less errors compared to not doing it.
        if self.password:
            m = HEX_PATTERN.search(self.password)
            if m:
                bin_p = binascii.unhexlify(m.group("hexascii"))
                self.password = bin_p.decode(errors="ignore")

    def is_disabled(self):
        if self.comment and "status=Disabled" in self.comment:
            return True
        return False

    def is_computer_account(self):
        return self.username.endswith("$")

    def __eq__(self, b):
        if b is None:
            return False
        if isinstance(b, User):
            b = b.username
        if not isinstance(b, str):
            raise TypeError("Can't compare User object with type %s" % type(b).__name__)
        return self.username.lower() == b.lower()

    def __hash__(self):
        return hash(self.username.lower())

    def __str__(self):
        return self.full_username

    def __repr__(self):
        return "<User: %s>" % str(self)

    def as_json(self):
        # needed so this can be serialized by the reporting module
        return str(self)


def line_binary_search(filename, matchvalue, key=lambda val: val, start=0):
    """
    Binary search a file for matching lines.

    Returns a list of matching lines.

    filename - path to file, passed to 'open'
    matchvalue - value to match
    key - function to extract comparison value from line

    >>> parser = lambda val: int(val.split('\t')[0].strip())
    >>> line_binary_search('sd-arc', 63889187, parser)
    ['63889187\t3592559\n', ...]

    Source:
    http://www.grantjenks.com/wiki/random/python_binary_search_file_by_line
    """

    # Must be greater than the maximum length of any line.

    max_line_len = 2**8

    pos = start
    end = os.path.getsize(filename)

    with open(filename, "rb") as fptr:
        # Limit the number of times we binary search.
        for rpt in range(50):
            last = pos
            pos = start + ((end - start) // 2)
            fptr.seek(pos)

            # Move the cursor to a newline boundary.
            fptr.readline()
            line = fptr.readline()
            linevalue = key(line)

            if linevalue == matchvalue or pos == last:
                # Seek back until we no longer have a match.
                while True:
                    try:
                        fptr.seek(-max_line_len, 1)
                    except OSError:
                        # We seek'ed beyond the beginning of the file
                        fptr.seek(0)
                        break
                    fptr.readline()
                    if matchvalue != key(fptr.readline()):
                        break

                # Seek forward to the first match.
                for rpt in range(max_line_len):
                    line = fptr.readline()
                    linevalue = key(line)
                    if matchvalue == linevalue:
                        # Assume each line is unique
                        return matchvalue, fptr.tell()
                else:
                    # No match was found.
                    return None, None

            elif linevalue < matchvalue:
                start = fptr.tell()
            else:
                assert linevalue > matchvalue
                end = fptr.tell()
        else:
            raise RuntimeError("binary search failed")
