from datetime import datetime as dt
import collections
import logging
import re

from hashcathelper.consts import NT_EMPTY, LM_EMPTY
from hashcathelper.utils import prcnt, User

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


def get_top_basewords(passwords):
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
    return counts.most_common(10)


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


def load_lines(path, as_user=True):
    result = []
    if path:
        with open(path, 'r', encoding="utf-8", errors="replace") as f:
            for line in f.readlines():
                if as_user:
                    try:
                        result.append(User(line))
                    except Exception as e:
                        log.error(str(e))
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


def analyze_passwords(report, passwords):
    if 'accounts' not in report:
        report['accounts'] = len(passwords)
    if 'total_accounts' not in report:
        report['total_accounts'] = len(passwords)
    lengths = [len(p) for p in passwords]
    report['average_password_length'] = average(lengths)
    report['median_password_length'] = median(lengths)
    report['password_length_count'] = sort_dict(
        collections.Counter(lengths)
    )
    char_classes = get_char_classes(passwords)
    report['char_class_count'] = sort_dict(char_classes)
    report['average_character_classes'] = int(sum(
        k*v for k, v in char_classes.items()
    ) / len(passwords) * 100) / 100

    report['top10_passwords'] = collections.OrderedDict(
        filter(
            lambda x: x[1] > 1,
            collections.Counter(passwords).most_common(10),
        )
    )
    report['top10_basewords'] = collections.OrderedDict(
        get_top_basewords(passwords)
    )

    if 'cluster_count' not in report:
        cluster_analysis(report, passwords, empty='')


def count_user_equal_password(report, accounts_plus_passwords):
    count = 0
    for u in accounts_plus_passwords:
        if u == u.password:
            count += 1
    report['user_equals_password'] = (
        count,
        prcnt(count, len(accounts_plus_passwords)),
    )


def analyze_hashes(report, hashes, passwords):
    report['accounts'] = len(hashes)
    if 'total_accounts' not in report:
        report['total_accounts'] = len(hashes)
    if passwords:
        report['cracked'] = (
            len(passwords),
            prcnt(len(passwords), len(hashes)),
        )
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

    report['lm_hash_count'] = (
        lm_hash_count,
        prcnt(lm_hash_count, report['accounts']),
    )

    # Clusters
    nt_hashes = [u.nthash for u in hashes]
    cluster_analysis(report, nt_hashes, empty=NT_EMPTY)


def remove_accounts(report, accounts_plus_passwords, hashes, remove=[],
                    keep_only=[]):
    """Remove all lines from `hashes` and `accounts_plus_passwords` which have a
    username which is either specified in `remove` or not specified in
    `keep_only` (if `keep_only` is non-empty).

    Accounts are assumed to be case-insensitive. The UPN suffix (e.g. the
    domain name) is ignored if there is one.

    `report` must be a suitable dictionary, the other args lists of `User()`.
    """

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
        report['total_accounts'] = before
        report['removed'] = before - after

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
        report['total_accounts'] = before
        report['removed'] = before - after

    return accounts_plus_passwords, hashes


def create_report(hashes=None, accounts_plus_passwords=None, passwords=None,
                  filter_accounts=None, pw_min_length=6,
                  include_disabled=False, include_computer_accounts=False):
    log.info("Creating report...")
    report = collections.OrderedDict()

    do_sanity_check(hashes, accounts_plus_passwords, passwords,
                    filter_accounts)
    meta = collections.OrderedDict(
        filename_hashes=hashes,
        filename_result=accounts_plus_passwords,
        filename_passwords=passwords,
        filename_filter=filter_accounts,
        timestamp=str(dt.now()),
    )

    # Load data from files
    hashes = load_lines(hashes)
    accounts_plus_passwords = load_lines(accounts_plus_passwords)
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
    print(disabled)

    # Filter accounts
    if filter_accounts:
        log.info("Only taking specified accounts into consideration")
    if disabled:
        log.info("Removing %d accounts which have been marked as disabled"
                 % len(disabled))
    if computer_accounts:
        log.info("Removing %d computer accounts" % len(computer_accounts))

    accounts_plus_passwords, hashes = remove_accounts(
        report,
        accounts_plus_passwords,
        hashes,
        remove=disabled+computer_accounts,
        keep_only=filter_accounts,
    )
    if report['removed'] == 0:
        log.warning(
            "No accounts filtered. Are you sure?"
            " At least inactive accounts should be filtered."
        )

    # Count accounts where user==password
    if accounts_plus_passwords:
        count_user_equal_password(report, accounts_plus_passwords)

    # Remove account names now that they are filtered
    if not passwords and accounts_plus_passwords:
        passwords = [u.password for u in accounts_plus_passwords]

    # Analyze hashes only
    if hashes:
        analyze_hashes(report, hashes, passwords)

    # Analyze passwords
    if passwords:
        analyze_passwords(report, passwords)

    # Move sensitive information
    sensitive = collections.OrderedDict()
    for k in ['top10_passwords', 'top10_basewords']:
        if k in report:
            sensitive[k] = report[k]
            del report[k]

    # Find accounts with short passwords
    details = {
        'short_password': {i: [] for i in range(pw_min_length)},
        'user_equals_password': [],
        'user_similarto_password': [],
    }
    for u in accounts_plus_passwords:
        if len(u.password) < pw_min_length:
            details['short_password'][len(u.password)].append(u.username)
        if u.username.lower() == u.password.lower():
            details['user_equals_password'].append(u.username)
        elif (u.password and (
            u.username.lower() in u.password.lower()
            or u.password.lower() in u.username.lower()
        )):
            details['user_similarto_password'].append(u.username)

    result = collections.OrderedDict(
        meta=meta,
        report=report,
        sensitive=sensitive,
        details=details,
    )
    return result


def cluster_analysis(report, values, empty=''):
    counter = collections.Counter(values)
    clusters = dict(c for c in counter.most_common() if c[1] > 1)
    report['cluster_count'] = sort_dict(collections.Counter(
        c for c in clusters.values() if c > 1
    ))

    if 'accounts' in report:
        total = report['accounts']
    else:
        total = len(values)

    nonunique = sum(count for _, count in counter.items() if count > 1)
    report['nonunique'] = (nonunique, prcnt(nonunique, total))

    report['empty_password'] = (
        counter[empty],
        prcnt(counter[empty], total),
    )
