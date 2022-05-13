import argparse
import logging

from hashcathelper.args import subcommand, argument

log = logging.getLogger(__name__)
args = []


args.append(argument(
    dest='infile',
    type=argparse.FileType('r'),
    help="path to a report file in JSON format",
))


args.append(argument(
    dest='bloodhound_url',
    help="""
URL to a Neo4j database containing BloodHound data. Format:
bolt://<user>:<password>@<host>:<port>"""
))


args.append(argument(
    dest='domain',
    help="""specify the domain of the accounts"""
))


@subcommand(args)
def bloodhound(args):
    '''Add 'SamePassword' edges to a BloodHound database'''
    import json

    from hashcathelper.bloodhound import get_driver, add_edges

    data = json.load(args.infile)
    if 'details' not in data or 'clusters' not in data['details']:
        log.critical("No information about clusters found in report file")
        exit(1)
    clusters = data['details']['clusters'].values()
    driver = get_driver(args.bloodhound_url)
    add_edges(driver, clusters, args.domain)
