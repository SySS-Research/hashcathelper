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
    dest='bloodhound_url',
    help="""
URL to a Neo4j database containing BloodHound data. Format:
bolt[s]://<user>:<password>@<host>:<port>"""
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
    import json
    import collections

    from hashcathelper.bloodhound import get_driver, add_edges

    clusters = collections.defaultdict(lambda: [])
    for (domain, infile) in args.domain_infile:
        log.info("Reading file: %s" % infile.name)
        data = json.load(infile)
        if 'details' not in data or 'clusters' not in data['details']:
            log.critical("No information about clusters found in report file")
            exit(1)

        for password, usernames in data['details']['clusters'].items():
            clusters[password].extend([u + '@' + domain for u in usernames])

    driver = get_driver(args.bloodhound_url)
    add_edges(driver, clusters.values())
