import collections
import logging
import re

from .consts import NT_EMPTY, LM_EMPTY

log = logging.getLogger(__name__)


labels = dict(
    total_accounts="Total number of accounts",
    removed='Accounts removed from analysis',
    accounts='Accounts subject to analysis',
    cracked='Accounts where password was cracked',
    cracked_percentage='Percentage of accounts where password was cracked',
    lm_hash_count='Accounts with a non-empty LM hash',
    lm_hash_count_percentage='Percentage of accounts with a non-empty LM hash',
    unique='Accounts with unique password',
    unique_percentage='Percentage of accounts with unique password',
    empty_password='Accounts with an empty password',
    empty_password_percentage='Percentage of accounts with an empty password',
    average_password_length='Average length of cracked passwords',
    median_password_length='Median length of cracked passwords',
    top10_passwords='Top 10 Passwords',
    top10_basewords='Top 10 Basewords',
    char_class_count='Character classes',
    average_character_classes='Average number of character classes of'
    ' cracked passwords',
    password_length_count='Lengths of cracked passwords',
    cluster_count='Cluster sizes',
    user_equals_password='Accounts where username equals the password',
    user_equals_password_percentage='Percentage of '
    'accounts where username equals the password',
)


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


def load_lines(path):
    if path:
        with open(path, 'r', encoding="utf-8", errors="replace") as f:
            content = f.read()
        result = content.splitlines()
    else:
        result = []
    return result


def sort_dict(dct):
    return collections.OrderedDict(sorted(dct.items()))


def prcnt(a, b):
    return int(a/b * 100 * 100)/100


def create_report(hashes=None, accounts_plus_passwords=None, passwords=None,
                  filter_accounts=None, censor=False):
    # TODO refactor this long function
    log.info("Creating report...")
    report = {}

    # Sanity check
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
            "if neither hashes nor accounts_plus_passwords is None"
        )

    # Load data from files
    hashes = load_lines(hashes)
    accounts_plus_passwords = load_lines(accounts_plus_passwords)
    passwords = load_lines(passwords)
    filter_accounts = load_lines(filter_accounts)

    pattern = re.compile(r'([^\\]+\\)?(?P<name>[^:]+):.*$')

    def get_account_name(line):
        name = pattern.search(line).group('name').lower()
        return name

    # Filter accounts
    if filter_accounts:
        log.info("Only taking specified accounts into consideration")
        filter_accounts = set(line.lower() for line in filter_accounts)
        if accounts_plus_passwords:
            before = len(accounts_plus_passwords)
            accounts_plus_passwords = [
                p for p in accounts_plus_passwords
                if get_account_name(p) in filter_accounts
            ]
            after = len(accounts_plus_passwords)
            report['total_accounts'] = before
            report['removed'] = before - after
        if hashes:
            before = len(hashes)
            hashes = [h for h in hashes
                      if get_account_name(h) in filter_accounts]
            after = len(hashes)
            report['total_accounts'] = before
            report['removed'] = before - after
    else:
        report['removed'] = 0

    # Count accounts where user==password
    if accounts_plus_passwords:
        count = 0
        for line in accounts_plus_passwords:
            user = line.split(':')[0]
            password = ':'.join(line.split(':')[1:])
            if '\\' in user:
                user = user.split('\\')[1]
            if user.lower() == password.lower():
                count += 1
        report['user_equals_password'] = count
        report['user_equals_password_percentage'] = \
            prcnt(count, len(accounts_plus_passwords))

    # Remove account names now that they are filtered
    if not passwords:
        passwords = [':'.join(line.split(':')[1:])
                     for line in accounts_plus_passwords]

    # Analyze hashes only
    if hashes:
        report['accounts'] = len(hashes)
        if 'total_accounts' not in report:
            report['total_accounts'] = len(hashes)
        if passwords:
            report['cracked'] = len(passwords)
            report['cracked_percentage'] = \
                prcnt(len(passwords), len(hashes))
        lm_hash_count = 0
        for line in hashes:
            if ':%s:' % LM_EMPTY not in line:
                lm_hash_count += 1
        report['lm_hash_count'] = lm_hash_count
        report['lm_hash_count_percentage'] = \
            prcnt(lm_hash_count, report['accounts'])

        # Clusters
        nt_hashes = [line.split(':')[3] for line in hashes]
        cluster_analysis(report, nt_hashes, empty=NT_EMPTY)

    # Analyze passwords
    if passwords:
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

    if censor:
        sensitive_fields = [
            'top10_basewords',
            'top10_passwords',
        ]
        for f in sensitive_fields:
            if f in report:
                del report[f]

    return report


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

    report['unique'] = sum(1 for _, count in counter.items()
                           if count == 1)
    report['unique_percentage'] = prcnt(report['unique'], total)

    report['empty_password'] = counter[empty]
    report['empty_password_percentage'] = \
        prcnt(report['empty_password'], total)
