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
    regex = r'^bolt://(?P<user>[^:]+):(?P<password>.+)@'
    regex += r'(?P<host>.*):(?P<port>[0-9]+)$'
    m = re.match(regex, url)

    user, password, host, port = m.groups()

    url = "bolt://%s:%s" % (host, port)

    log.debug("Connecting to %s..." % url)
    driver = GraphDatabase.driver(url, auth=(user, password))

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
    rel_count = 0
    log.info("Processing %d clusters..." % len(clusters))
    with driver.session() as session:
        for cluster in clusters:
            # Only create clusters instead of cliques. In cliques, the
            # number of edges grows as n^2, which can become overwhelming
            # and doesn't add much value.
            if len(cluster) <= 1:
                continue
            node_a = cluster[0]
            for node_b in cluster[1:]:
                try:
                    session.write_transaction(
                        add_single_edge,
                        node_a, node_b, domain
                    )
                    session.write_transaction(
                        add_single_edge,
                        node_b, node_a, domain
                    )
                    rel_count += 1
                except Exception as e:
                    log.error(
                        "Error adding relationship %s -> %s: %s"
                        % (node_a, node_b, str(e))
                    )
    log.info("Added %d relationships to BloodHound" % rel_count)


def add_single_edge(tx, node_a, node_b, domain):
    q = """
    MATCH (a:User), (b:User)
    WHERE a.name =~ '(?i)%(node_a)s@%(domain)s'
    AND b.name =~ '(?i)%(node_b)s@%(domain)s'
    CREATE (a)-[r:SamePassword]->(b)
    RETURN type(r)
    """ % dict(
        node_a=node_a,
        node_b=node_b,
        domain=domain,
    )

    result = tx.run(q)
    if len(result.value()) == 0:
        raise KeyError(
            "Node(s) not found: %s@%s, %s@%s"
            % (node_a, domain, node_b, domain))
