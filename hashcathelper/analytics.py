from datetime import datetime as dt
import collections
import logging
import re

from hashcathelper.consts import NT_EMPTY, LM_EMPTY
from hashcathelper.utils import User, get_nthash, line_binary_search
from hashcathelper.reporting import (
    Table,
    Report,
    Section,
    Histogram,
    RelativeQuantity,
    LongTable,
    List,
)

log = logging.getLogger(__name__)


def median(lst):
    sortedLst = sorted(lst)
    lstLen = len(lst)
    index = (lstLen - 1) // 2

    if lstLen % 2:
        return sortedLst[index]
    else:
        return (sortedLst[index] + sortedLst[index + 1]) / 2.0


def average(lst):
    return int(100 * sum(lst) / len(lst)) / 100


def get_top_passwords(passwords, n=10):
    return Histogram(
        collections.OrderedDict(
            filter(
                lambda x: x[1] > 1,
                collections.Counter(passwords).most_common(n),
            )
        ),
        "top10_passwords",
    )


def get_top_basewords(passwords, n=10):
    counts = collections.Counter()
    for p in passwords:
        if not p:
            continue
        # Convert to lower case
        p = p.lower()

        # Remove special chars and digits from beginning and end
        p = re.sub("[0-9!@#$%^&*()=_+~{}|\"? ><,./\\'[\\]-]*$", "", p)
        p = re.sub("^[0-9!@#$%^&*()=_+~{}|\" ?><,./\\'[\\]-]*", "", p)

        # De-leet-ify
        p = p.replace("!", "i")
        p = p.replace("1", "i")
        p = p.replace("0", "o")
        p = p.replace("3", "e")
        p = p.replace("4", "a")
        p = p.replace("@", "a")
        p = p.replace("+", "t")
        p = p.replace("$", "s")
        p = p.replace("5", "s")

        # Remove remaining special chars
        p = re.sub("[!@#$%^&*()=_+~{}|\"?><,./\\'[\\]-]", "", p)

        # Forget this if it's empty by now
        if not p:
            continue

        # Is it multiple words? Get the longest
        p = sorted(p.split(), key=len)[-1]

        # If there are digits left (i.e. it's not a word) or the word is
        # empty, we're not interested anymore
        if not re.search("[0-9]", p) and p:
            counts.update([p])

    # Remove basewords shorter than 3 characters or occurance less than 2
    for k in counts.copy():
        if counts[k] == 1 or len(k) < 3:
            del counts[k]
    top10 = collections.OrderedDict(counts.most_common(n))
    return Histogram(top10, "top10_basewords")


def get_char_classes(passwords):
    counts = collections.Counter()
    for p in passwords:
        classes = get_character_classes(p)
        counts.update([classes])
    return counts


def get_character_classes(password):
    upper = False
    lower = False
    digits = False
    chars = False
    if re.search("[A-Z]", password):
        upper = True
    if re.search("[a-z]", password):
        lower = True
    if re.search("[0-9]", password):
        digits = True
    if re.search("[^A-Za-z0-9]", password):
        chars = True
    result = sum([upper, lower, digits, chars])
    return result


def load_lines(path, as_user=True):
    """Load file and parse each line as `User()`"""
    if not path:
        return []

    result = []
    with open(path, "r", encoding="utf-8", errors="backslashreplace") as f:
        for i, line in enumerate(f.readlines()):
            if as_user:
                try:
                    result.append(User(line))
                except Exception as e:
                    log.error("Error while parsing line %s:%d: %s" % (path, i, str(e)))
            else:
                result.append(line)
    return result


def sort_dict(dct):
    return collections.OrderedDict(sorted(dct.items()))


def do_sanity_check(hashes, accounts_plus_passwords, passwords, filter_accounts):
    """Make sure the right combination of files was passed"""
    if not (hashes or accounts_plus_passwords or passwords):
        log.error("No files specified, nothing to do")
        exit(1)

    if passwords and accounts_plus_passwords:
        log.warning(
            "accounts_plus_passwords specified, ignoring passwords file: " + passwords
        )

    if filter_accounts and not (hashes or accounts_plus_passwords):
        log.warning(
            "filter_accounts specified, but not needed "
            "if neither hashes nor accounts_plus_passwords is given"
        )


def analyze_passwords(table, passwords):
    if "accounts" not in table:
        table["accounts"] = len(passwords)
    if "total_accounts" not in table:
        table["total_accounts"] = len(passwords)
    lengths = [len(p) for p in passwords]
    table["average_password_length"] = average(lengths)
    table["median_password_length"] = median(lengths)
    password_length_count = Histogram(
        sort_dict(collections.Counter(lengths)),
        "password_length_count",
    )
    char_classes = get_char_classes(passwords)
    char_class_count = Histogram(sort_dict(char_classes), "char_class_count")
    table["average_character_classes"] = (
        int(sum(k * v for k, v in char_classes.items()) / len(passwords) * 100) / 100
    )

    return password_length_count, char_class_count


def count_user_equal_password(table, accounts_plus_passwords, total):
    count = 0
    for u in accounts_plus_passwords:
        if u == u.password:
            count += 1
    table["user_equals_password"] = RelativeQuantity(count, total)


def analyze_hashes(table, hashes, passwords):
    table["accounts"] = len(hashes)
    if "total_accounts" not in table:
        table["total_accounts"] = len(hashes)
    if passwords:
        table["cracked"] = RelativeQuantity(len(passwords), len(hashes))
    lm_hash_count = 0
    computer_acc_count = 0
    for u in hashes:
        if u.lmhash != LM_EMPTY:
            lm_hash_count += 1
        if u.is_computer_account():
            computer_acc_count += 1

    if computer_acc_count:
        log.warning(
            "%d computer accounts found in hash file. You should remove these."
            % computer_acc_count
        )

    table["lm_hash_count"] = RelativeQuantity(lm_hash_count, table["accounts"])


def remove_accounts(table, accounts_plus_passwords, hashes, remove=[], keep_only=[]):
    """Remove all lines from `hashes` and `accounts_plus_passwords` which
    have a username which is either specified in `remove` or not specified
    in `keep_only` (if `keep_only` is non-empty).

    Accounts are assumed to be case-insensitive. The UPN suffix (e.g. the
    domain name) is ignored if there is one.

    `table` must be a suitable dictionary, the other args lists of `User()`.
    """
    remove_set = set(remove)
    keep_set = set(keep_only)
    # Remove entries from first list
    if accounts_plus_passwords:
        before = len(accounts_plus_passwords)
        accounts_plus_passwords = [
            u for u in accounts_plus_passwords if u not in remove_set
        ]
        if keep_only:
            accounts_plus_passwords = [
                u for u in accounts_plus_passwords if u in keep_set
            ]
        after = len(accounts_plus_passwords)
        table["total_accounts"] = before
        table["removed"] = before - after

    # Remove entries from second list
    if hashes:
        before = len(hashes)
        hashes = [u for u in hashes if u not in remove_set]
        if keep_only:
            hashes = [u for u in hashes if u in keep_set]
        after = len(hashes)
        table["total_accounts"] = before
        table["removed"] = before - after

    return accounts_plus_passwords, hashes


def get_hibp(hashes, hibp_db):
    """Look up how many hashes are in the HIBP database

    HIBP stands for Have I been Pwned. The HIBP database must be a flat,
    sorted text file of NT hashes in the format `<NT hash in upper
    case>:<count>`.

    Arguments:
        hashes: a list of `User` objects
        hibp_db: path to the HIBP database

    Returns:
        A list of affected usernames
    """

    pos = 0
    result = []
    hashes.sort(key=lambda x: x.nthash)
    for u in hashes:
        h = u.nthash.upper().encode()
        results, new_pos = line_binary_search(
            hibp_db,
            h,
            lambda line: line[:32],
            start=pos,
        )
        if results:
            pos = new_pos
            result.append(u.username)
        else:
            pass
    return List("hibp_accounts", result)


def create_report(
    hashes=None,
    accounts_plus_passwords=None,
    passwords=None,
    filter_accounts=[],
    pw_min_length=6,
    pw_complexity=False,
    degree_of_detail=1,
    include_disabled=False,
    include_computer_accounts=False,
    hibp_db=None,
):
    """Create the report on password statistics

    Arguments:
        hashes: path to the output file from secretsdump or similar
        accounts_plus_passwords: path to the output file of hashcat with
            user names
        passwords: path to a file containing only passwords (one per line)
        filter_accounts: list of `User` objects, which will be the only ones
            considered
        pw_min_length: definition of a password that is 'too short'
        degree_of_detail (int): amount of detail to include
        include_disabled: don't remove disabled accounts
        include_computer_accounts: don't remove computer accounts
        hibp_db: path to the HIBP database (sorted by NT hash)
    """
    log.info("Creating report...")
    table = Table("key_quantities", collections.OrderedDict())

    do_sanity_check(hashes, accounts_plus_passwords, passwords, filter_accounts)
    meta = Table(
        "meta",
        collections.OrderedDict(
            filename_hashes=hashes,
            filename_result=accounts_plus_passwords,
            filename_passwords=passwords,
            filename_filter=filter_accounts,
            timestamp=str(dt.now()),
        ),
        formats=["json"],
    )

    # Load data from files
    hashes = load_lines(hashes)
    accounts_plus_passwords = load_lines(accounts_plus_passwords)
    passwords = load_lines(passwords, as_user=False)

    # Remove computer accounts and accounts marked by hashcat as 'disabled'
    disabled = []
    computer_accounts = []
    if not include_disabled or not include_computer_accounts:
        for u in hashes:
            if u.is_disabled() and not include_disabled:
                disabled.append(u)
            if u.is_computer_account() and not include_computer_accounts:
                computer_accounts.append(u)

    cracked_computer_accounts = set(computer_accounts).intersection(
        accounts_plus_passwords
    )

    # Filter accounts
    log.debug("Filter accounts")
    if filter_accounts:
        log.info(
            "Removing all accounts which are not in filter (%d)" % len(filter_accounts)
        )
    if disabled:
        log.info(
            "Removing %d accounts which have been marked as disabled" % len(disabled)
        )
    if computer_accounts:
        log.info("Removing %d computer accounts" % len(computer_accounts))

    accounts_plus_passwords, hashes = remove_accounts(
        table,
        accounts_plus_passwords,
        hashes,
        remove=disabled + computer_accounts,
        keep_only=filter_accounts,
    )
    if table["removed"] == 0:
        log.warning(
            "No accounts filtered. Are you sure?"
            " At least inactive accounts should be filtered."
        )
    log.debug("Removed %d accounts" % table["removed"])

    # Count cracked computer accounts
    table["cracked_computer_accounts"] = len(cracked_computer_accounts)

    # Count accounts where user==password
    if accounts_plus_passwords:
        count_user_equal_password(table, accounts_plus_passwords, len(hashes))

    # Remove account names now that they are filtered
    if not passwords and accounts_plus_passwords:
        passwords = [u.password for u in accounts_plus_passwords]

    # Analyze hashes only
    log.debug("Analyze hashes")
    if hashes:
        analyze_hashes(table, hashes, passwords)
        nt_hashes = [u.nthash for u in hashes]
        clusters = cluster_analysis(table, nt_hashes, empty=NT_EMPTY)

    # Analyze passwords
    log.debug("Analyze passwords")
    if passwords:
        password_length_count, char_class_count = analyze_passwords(table, passwords)
        if not hashes:
            clusters = cluster_analysis(table, passwords, empty="")
    else:
        password_length_count, char_class_count = None, None

    sort_table(table)

    result = Report("report")
    result += meta

    if degree_of_detail > 0:
        statistics = Section("statistics")
        statistics += table
        statistics += clusters
        if password_length_count:
            statistics += password_length_count
        if char_class_count:
            statistics += char_class_count
        result += statistics

    if degree_of_detail > 1:
        log.debug("Get top passwords")
        s = Section("sensitive_data")
        s += get_top_passwords(passwords)
        s += get_top_basewords(passwords)
        result += s

    if degree_of_detail > 2:
        # Add details: accounts with short passwords; clusters
        details = gather_details(
            hashes,
            accounts_plus_passwords,
            pw_min_length,
            pw_complexity,
            hibp_db,
        )
        details += List(
            "cracked_computer_accounts",
            cracked_computer_accounts,
        )
        result += details

    if degree_of_detail > 3:
        # Add all known credentials
        creds = gather_creds(
            hashes,
            accounts_plus_passwords,
        )
        result += creds

    return result


def gather_creds(hashes, accounts_plus_passwords):
    """Return a dictionary with credentials"""
    creds = LongTable(
        "full_creds",
        dict(
            sorted({u.username: [u.password] for u in accounts_plus_passwords}.items())
        ),
    )
    return creds


def gather_details(
    hashes, accounts_plus_passwords, pw_min_length, pw_complexity, hibp_db
):
    """Return a dictionary with details about the report

    Contains:
        * list of accounts with short passwords
        * list of accounts where password does not meet AD complexity requirements
        * list of accounts where usename equals password (case insensitive)
        * list of accounts where usename is similar to password (starts or
          ends with password, case insensitive)
        * list of clusters; either based on hash or based on password if
          cracked
    """
    short_password = LongTable(
        "short_password",
        collections.OrderedDict((i, []) for i in range(pw_min_length)),
    )
    if pw_complexity:
        password_not_complex = List("password_not_complex", [])
    user_equals_password = List("user_equals_password", [])
    user_similarto_password = List("user_similarto_password", [])

    for u in accounts_plus_passwords:
        if len(u.password) < pw_min_length:
            short_password[len(u.password)].append(u.username)
        if pw_complexity:
            if not password_satisfies_complexity_requirements(u.username, u.password):
                password_not_complex.append(u.username)
        if u.username.lower() == u.password.lower():
            user_equals_password.append(u.username)
        elif u.password and (
            u.username.lower() in u.password.lower()
            or u.password.lower() in u.username.lower()
        ):
            user_similarto_password.append(u.username)

    # Find clusters
    clusters = collections.defaultdict(list)
    for u in hashes:
        clusters[u.nthash].append(u.username)

    # Remove non-clusters
    for h in list(clusters.keys()):
        if len(clusters[h]) == 1:
            del clusters[h]

    # Replace hashes with passwords where possible
    # Build dict of nthash->password to avoid n^2 loop
    hash_map = {
        get_nthash(u.password.encode()): u.password for u in accounts_plus_passwords
    }

    for h in list(clusters.keys()):
        if h in hash_map:
            clusters[hash_map[h]] = clusters[h]
            del clusters[h]

    # Sort clusters by size
    clusters = collections.OrderedDict(
        sorted([(k, v) for k, v in clusters.items()], key=lambda x: -len(x[1]))
    )

    clusters = LongTable("clusters", clusters)

    # Build section
    details = Section("details")
    details += clusters
    details += user_equals_password
    details += user_similarto_password
    details += short_password
    if pw_complexity:
        details += password_not_complex
    if hibp_db:
        try:
            details += get_hibp(hashes, hibp_db)
        except FileNotFoundError:
            log.error("Could not include HIBP stats; file not found: %s" % hibp_db)
    else:
        log.error("No HIBP database defined; skipping this detail")
    return details


def password_satisfies_complexity_requirements(samaccountname, password):
    """
    Check, whether given password satisfies complexity requirements listed in
    https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994562(v=ws.11)
    """

    if samaccountname.lower() in password.lower():
        return False

    # Displayname requirements are ignored since that data is not available here.

    return get_character_classes(password) >= 3


def cluster_analysis(table, values, empty=""):
    counter = collections.Counter(values)
    clusters = dict(c for c in counter.most_common() if c[1] > 1)
    cluster_count = Histogram(
        sort_dict(collections.Counter(c for c in clusters.values() if c > 1)),
        "cluster_count",
    )

    if "accounts" in table:
        total = table["accounts"]
    else:
        total = len(values)

    nonunique = sum(count for _, count in counter.items() if count > 1)
    table["nonunique"] = RelativeQuantity(nonunique, total)

    table["empty_password"] = RelativeQuantity(counter[empty], total)
    return cluster_count


def sort_table(table):
    """Sort entries of table like the labels"""
    from hashcathelper.consts import labels

    result = collections.OrderedDict()
    for k in labels.keys():
        if k in table:
            result[k] = table[k]
            del table[k]
    table_copy = collections.OrderedDict(table)
    for k, v in table_copy.items():
        result[k] = v
        del table[k]
    table.update(result)


def create_short_report(
    submitter_email,
    wordlist,
    rule_set,
    hashcat_version,
    data,
):
    """Produce a dictionary that can be submitted to the DB"""

    from datetime import datetime as dt
    from hashcathelper._meta import __version__

    try:
        timestamp = data["meta"]["timestamp"]
        cracking_date = dt.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
    except (KeyError, ValueError):
        log.error("Failed to parse cracking date")
        cracking_date = None

    key_quantities = data["statistics"]["key_quantities"]

    def get_value(item):
        # for values with percentage
        val = key_quantities[item]
        if isinstance(val, list) and len(val) == 2:
            return val[0]
        return val

    top_basewords = data["sensitive_data"]["top10_basewords"].values()
    if top_basewords:
        largest_cluster = max(top_basewords)
    else:
        largest_cluster = 0
    r = dict(
        submitter_email=submitter_email,
        submission_date=dt.now(),
        cracking_date=cracking_date,
        wordlist=wordlist,
        rule_set=rule_set,
        hashcathelper_version=__version__,
        hashcat_version=hashcat_version,
        accounts=key_quantities["accounts"],
        cracked=get_value("cracked"),
        nonunique=get_value("nonunique"),
        user_equals_password=get_value("user_equals_password"),
        lm_hash_count=get_value("lm_hash_count"),
        empty_password=get_value("empty_password"),
        average_password_length=key_quantities["average_password_length"],
        largest_baseword_cluster=largest_cluster,
    )
    return r
