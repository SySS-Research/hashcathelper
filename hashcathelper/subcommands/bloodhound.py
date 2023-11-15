import logging

from hashcathelper.args import subcommand, argument

log = logging.getLogger(__name__)
args = []


def domain_filepath_pair(arg):
    if ':' not in arg:
        log.critical("Argument contains no colon: %s. (Note the new argument format.)" % arg)
        exit(1)

    domain = arg.split(':')[0]
    filepath = arg[len(domain)+1:]

    if filepath.startswith('//') and '@' in filepath:
        log.critical("Unusual file path: %s. (Note the new argument format.)" % arg)
        exit(1)

    return domain, open(filepath, 'r')


args.append(argument(
    '-t', '--type',
    choices=['same_password', 'cracked'],
    default='same_password',
    help="type of data to add (`SamePassword` relationships or `cracked` boolean attribute; default: %(default)s)",
))


args.append(argument(
    dest='bloodhound_url',
    help="""
URL to a Neo4j database containing BloodHound data. Format:
bolt[s]://<user>:<password>@<host>[:<port>]"""
))


args.append(argument(
    dest='domain_infile',
    nargs='+',
    type=domain_filepath_pair,
    help="domain and path to a report file in JSON format. Format: <fqdn>:<file path>",
))


@subcommand(args)
def bloodhound(args):
    '''Add 'SamePassword' edges to a BloodHound database'''

    if args.type == 'same_password':
        add_samepassword_relationships(args)
    elif args.type == 'cracked':
        add_cracked_attribute(args)


def add_cracked_attribute(args):
    import json

    from hashcathelper.bloodhound import get_driver, mark_cracked

    users = []
    for (domain, infile) in args.domain_infile:
        log.info("Reading file: %s" % infile.name)
        data = json.load(infile)
        print(data.keys())
        if 'full_creds' not in data:
            log.critical("No information about cracked users found in report file (did you use `--degree-of-detail 4`?)")
            exit(1)

        users.extend(("%s@%s" % (user, domain)).upper() for user in data['full_creds'].keys())

    driver = get_driver(args.bloodhound_url)
    mark_cracked(driver, users)


def add_samepassword_relationships(args):
    import json
    import collections

    from hashcathelper.bloodhound import get_driver, add_edges

    clusters = collections.defaultdict(lambda: [])
    for (domain, infile) in args.domain_infile:
        log.info("Reading file: %s" % infile.name)
        data = json.load(infile)
        if 'details' not in data or 'clusters' not in data['details']:
            log.critical("No information about clusters found in report file (did you use `--degree-of-detail 3`?)")
            exit(1)

        for password, usernames in data['details']['clusters'].items():
            clusters[password].extend([u + '@' + domain for u in usernames])

    driver = get_driver(args.bloodhound_url)
    add_edges(driver, clusters.values())
