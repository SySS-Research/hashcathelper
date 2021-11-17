from datetime import datetime as dt
import collections
import logging
import re

from hashcathelper.consts import NT_EMPTY, LM_EMPTY
from hashcathelper.utils import User, get_nthash
from hashcathelper.reporting import Table, Report, Section, Histogram,\
    RelativeQuantity, LongTable, List

log = logging.getLogger(__name__)


def median(lst):
    sortedLst = sorted(lst)
    lstLen = len(lst)
    index = (lstLen - 1) // 2

    if (lstLen % 2):
        return sortedLst[index]
    else:
        return (sortedLst[index] + sortedLst[index + 1])/2.0


def average(lst):
    return int(100 * sum(lst)/len(lst))/100


def get_top_passwords(passwords, n=10):
    return Histogram(collections.OrderedDict(
        filter(
            lambda x: x[1] > 1,
            collections.Counter(passwords).most_common(n),
        )),
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
        p = re.sub('[0-9!@#$%^&*()=_+~{}|"? ><,./\\\'[\\]-]*$', '', p)
        p = re.sub('^[0-9!@#$%^&*()=_+~{}|" ?><,./\\\'[\\]-]*', '', p)

        # De-leet-ify
        p = p.replace('!', 'i')
        p = p.replace('1', 'i')
        p = p.replace('0', 'o')
        p = p.replace('3', 'e')
        p = p.replace('4', 'a')
        p = p.replace('@', 'a')
        p = p.replace('+', 't')
        p = p.replace('$', 's')
        p = p.replace('5', 's')

        # Remove remaining special chars
        p = re.sub('[!@#$%^&*()=_+~{}|"?><,./\\\'[\\]-]', '', p)

        # Forget this if it's empty by now
        if not p:
            continue

        # Is it multiple words? Get the longest
        p = sorted(p.split(), key=len)[-1]

        # If there are digits left (i.e. it's not a word) or the word is
        # empty, we're not interested anymore
        if not re.search('[0-9]', p) and p:
            counts.update([p])

    # Remove basewords shorter than 3 characters or occurance less than 2
    for k in counts.copy():
        if counts[k] == 1 or len(k) < 3:
            del counts[k]
    top10 = collections.OrderedDict(counts.most_common(n))
    return Histogram(top10, "top10_basewords")


def get_char_classes(passwords):
    def get_character_classes(s):
        upper = False
        lower = False
        digits = False
        chars = False
        if re.search('[A-Z]', s):
            upper = True
        if re.search('[a-z]', s):
            lower = True
        if re.search('[0-9]', s):
            digits = True
        if re.search('[^A-Za-z0-9]', s):
            chars = True
        result = sum([upper, lower, digits, chars])
        return result

    counts = collections.Counter()
    for p in passwords:
        classes = get_character_classes(p)
        counts.update([classes])
    return counts


def load_lines(path, as_user=True, encoding='utf-8'):
    """Load file and parse each line as `User()`"""
    if not path:
        return []

    result = []
    with open(path, 'r', encoding=encoding, errors='replace') as f:
        for i, line in enumerate(f.readlines()):
            if as_user:
                try:
                    result.append(User(line))
                except Exception as e:
                    log.error(
                        "Error while parsing line %s:%d: %s" %
                        (path, i, str(e))
                    )
            else:
                result.append(line)
    return result


def sort_dict(dct):
    return collections.OrderedDict(sorted(dct.items()))


def do_sanity_check(hashes, accounts_plus_passwords, passwords,
                    filter_accounts):
    """Make sure the right combination of files was passed"""
    if not (hashes or accounts_plus_passwords or passwords):
        log.error("No files specified, nothing to do")
        return {}

    if passwords and accounts_plus_passwords:
        log.warning(
            "accounts_plus_passwords specified, ignoring passwords file: "
            + passwords
        )

    if filter_accounts and not (hashes or accounts_plus_passwords):
        log.warning(
            "filter_accounts specified, but not needed "
            "if neither hashes nor accounts_plus_passwords is given"
        )


def analyze_passwords(table, passwords):
    if 'accounts' not in table:
        table['accounts'] = len(passwords)
    if 'total_accounts' not in table:
        table['total_accounts'] = len(passwords)
    lengths = [len(p) for p in passwords]
    table['average_password_length'] = average(lengths)
    table['median_password_length'] = median(lengths)
    password_length_count = Histogram(sort_dict(
        collections.Counter(lengths)
        ),
        'password_length_count',
    )
    char_classes = get_char_classes(passwords)
    char_class_count = Histogram(sort_dict(char_classes),
                                 'char_class_count')
    table['average_character_classes'] = int(sum(
        k*v for k, v in char_classes.items()
    ) / len(passwords) * 100) / 100

    return password_length_count, char_class_count


def count_user_equal_password(table, accounts_plus_passwords):
    count = 0
    for u in accounts_plus_passwords:
        if u == u.password:
            count += 1
    table['user_equals_password'] = RelativeQuantity(
        count,
        len(accounts_plus_passwords),
    )


def analyze_hashes(table, hashes, passwords):
    table['accounts'] = len(hashes)
    if 'total_accounts' not in table:
        table['total_accounts'] = len(hashes)
    if passwords:
        table['cracked'] = RelativeQuantity(len(passwords), len(hashes))
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

    table['lm_hash_count'] = RelativeQuantity(lm_hash_count, table['accounts'])


def remove_accounts(table, accounts_plus_passwords, hashes, remove=[],
                    keep_only=[]):
    """Remove all lines from `hashes` and `accounts_plus_passwords` which have a
    username which is either specified in `remove` or not specified in
    `keep_only` (if `keep_only` is non-empty).

    Accounts are assumed to be case-insensitive. The UPN suffix (e.g. the
    domain name) is ignored if there is one.

    `table` must be a suitable dictionary, the other args lists of `User()`.
    """
    # TODO performance is poor; improve

    # Remove entries from first list
    if accounts_plus_passwords:
        before = len(accounts_plus_passwords)
        accounts_plus_passwords = [
            u for u in accounts_plus_passwords
            if u not in remove
        ]
        if keep_only:
            accounts_plus_passwords = [
                u for u in accounts_plus_passwords
                if u in keep_only
            ]
        after = len(accounts_plus_passwords)
        table['total_accounts'] = before
        table['removed'] = before - after

    # Remove entries from second list
    if hashes:
        before = len(hashes)
        hashes = [
            u for u in hashes
            if u not in remove
        ]
        if keep_only:
            hashes = [u for u in hashes
                      if u in keep_only]
        after = len(hashes)
        table['total_accounts'] = before
        table['removed'] = before - after

    return accounts_plus_passwords, hashes


def create_report(hashes=None, accounts_plus_passwords=None,
                  passwords=None, filter_accounts=None, pw_min_length=6,
                  degree_of_detail=1, include_disabled=False,
                  include_computer_accounts=False):
    log.info("Creating report...")
    table = Table('key_quantities', collections.OrderedDict())

    do_sanity_check(hashes, accounts_plus_passwords, passwords,
                    filter_accounts)
    meta = Table(
        'meta',
        collections.OrderedDict(
            filename_hashes=hashes,
            filename_result=accounts_plus_passwords,
            filename_passwords=passwords,
            filename_filter=filter_accounts,
            timestamp=str(dt.now()),
        ),
        formats=['json'],
    )

    # Load data from files
    hashes = load_lines(hashes)
    # this file probably comes from hashcat, so assume extended ascii
    accounts_plus_passwords = load_lines(
        accounts_plus_passwords,
        encoding='ISO-8859-15',
    )
    passwords = load_lines(passwords, as_user=False)
    filter_accounts = load_lines(filter_accounts)

    # Remove computer accounts and accounts marked by hashcat as 'disabled'
    disabled = []
    computer_accounts = []
    if not include_disabled or not include_computer_accounts:
        for u in hashes:
            if u.is_disabled():
                disabled.append(u)
            if u.is_computer_account():
                computer_accounts.append(u)

    # Filter accounts
    log.debug("Filter accounts")
    if filter_accounts:
        log.info("Only taking specified accounts into consideration")
    if disabled:
        log.info("Removing %d accounts which have been marked as disabled"
                 % len(disabled))
    if computer_accounts:
        log.info("Removing %d computer accounts" % len(computer_accounts))

    accounts_plus_passwords, hashes = remove_accounts(
        table,
        accounts_plus_passwords,
        hashes,
        remove=disabled+computer_accounts,
        keep_only=filter_accounts,
    )
    if table['removed'] == 0:
        log.warning(
            "No accounts filtered. Are you sure?"
            " At least inactive accounts should be filtered."
        )
    log.debug("Removed %d accounts" % table['removed'])

    # Count accounts where user==password
    if accounts_plus_passwords:
        count_user_equal_password(table, accounts_plus_passwords)

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
        password_length_count, char_class_count = analyze_passwords(table,
                                                                    passwords)
        if not hashes:
            clusters = cluster_analysis(table, passwords, empty='')

    result = Report("report")
    result += meta

    if degree_of_detail > 0:
        statistics = Section("statistics")
        statistics += table
        statistics += clusters
        statistics += password_length_count
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
        )
        result += details

    return result


def gather_details(hashes, accounts_plus_passwords, pw_min_length):
    """Return a dictionary with details about the report

    Contains:
        * list of accounts with short passwords
        * list of accounts where usename equals password (case insensitive)
        * list of accounts where usename is similar to password (starts or
          ends with password, case insensitive)
        * list of clusters; either based on hash or based on password if
          cracked
    """
    short_password = LongTable(
        'short_password',
        collections.OrderedDict((i, []) for i in range(pw_min_length)),
    )
    user_equals_password = List('user_equals_password', [])
    user_similarto_password = List('user_similarto_password', [])

    for u in accounts_plus_passwords:
        if len(u.password) < pw_min_length:
            short_password[len(u.password)].append(u.username)
        if u.username.lower() == u.password.lower():
            user_equals_password.append(u.username)
        elif (u.password and (
            u.username.lower() in u.password.lower()
            or u.password.lower() in u.username.lower()
        )):
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
        get_nthash(u.password.encode()).decode(): u.password
        for u in accounts_plus_passwords
    }

    for h in list(clusters.keys()):
        if h in hash_map:
            clusters[hash_map[h]] = clusters[h]
            del clusters[h]
    clusters = LongTable('clusters', clusters)

    # Build section
    details = Section('details')
    details += clusters
    details += user_equals_password
    details += user_similarto_password
    details += short_password
    return details


def cluster_analysis(table, values, empty=''):
    counter = collections.Counter(values)
    clusters = dict(c for c in counter.most_common() if c[1] > 1)
    cluster_count = Histogram(sort_dict(collections.Counter(
            c for c in clusters.values() if c > 1
        )),
        'cluster_count',
    )

    if 'accounts' in table:
        total = table['accounts']
    else:
        total = len(values)

    nonunique = sum(count for _, count in counter.items() if count > 1)
    table['nonunique'] = RelativeQuantity(nonunique, total)

    table['empty_password'] = RelativeQuantity(counter[empty], total)
    return cluster_count


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
        timestamp = data['meta']['timestamp']
        cracking_date = dt.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
    except (KeyError, ValueError):
        log.error("Failed to parse cracking date")
        cracking_date = None

    key_quantities = data['statistics']['key_quantities']

    def get_value(item):
        # for values with percentage
        val = key_quantities[item]
        if isinstance(val, list) and len(val) == 2:
            return val[0]
        return val

    top_basewords = data['sensitive_data']['top10_basewords'].values()
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
        accounts=key_quantities['accounts'],
        cracked=get_value('cracked'),
        nonunique=get_value('nonunique'),
        user_equals_password=get_value('user_equals_password'),
        lm_hash_count=get_value('lm_hash_count'),
        empty_password=get_value('empty_password'),
        average_password_length=key_quantities['average_password_length'],
        largest_baseword_cluster=largest_cluster,
    )
    return r
