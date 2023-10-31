import logging

from neo4j import GraphDatabase

log = logging.getLogger(__name__)


CYPHER_QUERIES = {
    "enabled": "MATCH (u:User) WHERE u.enabled=true RETURN u",

    "kerberoastable": """
    MATCH (u:User)WHERE u.hasspn=true and u.enabled=true RETURN u
    """,

    "admincount": """
    MATCH (u:User)WHERE u.admincount=true AND u.enabled=true RETURN u
    """,

    "localadmins": """
    MATCH p = (u:User)-[:MemberOf|AdminTo*1..5]->(C:Computer)
    WHERE u.enabled=true RETURN DISTINCT u
    """,

    "domainadmins": """
    MATCH p = (u:User)-[:MemberOf*1..5]->(g:Group)
    WHERE g.objectid =~ '(?i)S-1-5-.*-512' AND u.enabled=true
    RETURN DISTINCT u
    """,

    #  "effective-domainadmins": "",
}


def get_driver(url):
    import re

    if not url:
        log.critical("No BloodHound URL given")
        exit(1)
    regex = r'^bolt(?P<encrypted>s?)://(?P<user>[^:]+):(?P<password>.+)@'
    regex += r'(?P<host>.*):(?P<port>[0-9]+)$'
    m = re.match(regex, url)
    if not m:
        log.error("Couldn't parse BloodHound URL: %s" % url)
        exit(1)

    encrypted, user, password, host, port = m.groups()
    encrypted = (encrypted == 's')

    url = "bolt://%s:%s" % (host, port)

    log.debug("Connecting to %s..." % url)
    driver = GraphDatabase.driver(url, auth=(user, password),
                                  encrypted=encrypted)

    return driver


def query_neo4j(driver, cypher_query, domain=None):
    """Query the neo4j for users

    If given, filter for domain and return `User()` objects.
    """
    from hashcathelper.utils import User

    log.debug("Given Cypher query: %s" % cypher_query)
    log.info("Querying BloodHound database...")

    q = CYPHER_QUERIES.get(cypher_query, cypher_query)
    result = []
    with driver.session() as session:
        for x in session.run(q).value():
            # if domain is specified, apply as a filter
            if not domain or x['domain'].lower() == domain.lower():
                u = User(x['name'])
                result.append(u)

    log.debug("Query result: %s" % result)
    return result


def add_edges(driver, clusters, domain):
    from tqdm import tqdm

    rel_count = 0
    log.info("Processing %d clusters..." % len(clusters))
    with driver.session() as session:
        for cluster in tqdm(clusters):
            # Only create clusters instead of cliques. In cliques, the
            # number of edges grows as n^2, which can become overwhelming
            # and doesn't add much value.
            if len(cluster) <= 1:
                continue
            edges = []
            node_a = cluster[0]
            for node_b in cluster[1:]:
                edges.append({
                    'a': '%s@%s' % (node_a, domain),
                    'b': '%s@%s' % (node_b, domain),
                    })
            added = session.write_transaction(add_many_edges, edges)
            rel_count += added
    log.info("Added %d relationships to BloodHound" % rel_count)


def add_many_edges(tx, edges):
    q = """
    UNWIND $edges as edge
    MATCH (a:User), (b:User)
    WHERE a.name = toUpper(edge.a)
    AND b.name = toUpper(edge.b)
    CREATE (a)-[r:SamePassword]->(b), (b)-[k:SamePassword]->(a)
    RETURN r
    """
    result = tx.run(q, edges=edges)
    return len(result.value())
