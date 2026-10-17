"""All Cypher in one place. The engine's Python metric (app/paths.py) is the
default for speed; the Cypher metric queries below are kept for the Aura
browser demo and cross-checking."""

WIPE = "MATCH (n) DETACH DELETE n"

WRITE_HOSTS = """
UNWIND $rows AS r
MERGE (h:Host {id: r.id})
SET h += r.props
"""

SET_CROWN_JEWEL = "MATCH (h:Host {id: $id}) SET h:CrownJewel"

WRITE_EDGES = """
UNWIND $rows AS r
MATCH (a:Host {id: r.src}), (b:Host {id: r.dst})
MERGE (a)-[e:CONNECTS_TO]->(b)
SET e.port = r.port, e.protocol = r.protocol, e.blocked = r.blocked
"""

WRITE_VULNS = """
UNWIND $rows AS r
MATCH (h:Host {id: r.host})
MERGE (v:Vuln {id: r.id})
SET v += r.props
MERGE (h)-[:HAS_VULN]->(v)
"""

WRITE_USERS = """
UNWIND $rows AS r
MERGE (u:User {id: r.id})
SET u += r.props
"""

WRITE_CREDS = """
UNWIND $rows AS r
MATCH (h:Host {id: r.stored_on}), (g:Host {id: r.grants}), (u:User {id: r.owner})
MERGE (c:Credential {id: r.id})
SET c += r.props
MERGE (h)-[:STORES]->(c)
MERGE (c)-[:GRANTS]->(g)
MERGE (u)-[:OWNS]->(c)
"""

WRITE_ADMIN_OF = """
UNWIND $rows AS r
MATCH (u:User {id: r.u}), (h:Host {id: r.h})
MERGE (u)-[:ADMIN_OF]->(h)
"""

# Generator guarantee check (>= 3 qualifying paths of length 4-8)
GUARANTEE = """
MATCH (i:Host {kind: 'internet'}), (cj:CrownJewel)
MATCH p = (i)-[:CONNECTS_TO*4..8]->(cj)
WHERE ALL(h IN nodes(p)[1..] WHERE
     EXISTS { (h)-[:HAS_VULN]->(:Vuln) }
  OR EXISTS { (:Credential)-[:GRANTS]->(h) })
WITH p LIMIT 3
RETURN count(p) AS n
"""

# Runtime viable-path count (Aura browser showcase / cross-check)
METRIC_PATHS = """
MATCH (cj:CrownJewel)
MATCH (s:Host) WHERE s.compromised OR s.kind = 'internet'
MATCH p = (s)-[:CONNECTS_TO*1..8]->(cj)
WHERE ALL(r IN relationships(p) WHERE NOT coalesce(r.blocked, false))
  AND ALL(h IN nodes(p) WHERE NOT h.isolated AND NOT h.honeypot)
  AND ALL(h IN nodes(p)[1..] WHERE
        h.compromised
     OR EXISTS { (h)-[:HAS_VULN]->(v:Vuln) WHERE NOT v.patched }
     OR EXISTS { (c:Credential)-[:GRANTS]->(h) WHERE c.stolen AND NOT c.rotated })
WITH p LIMIT 250
RETURN count(p) AS paths
"""

SHORTEST_PATH = """
MATCH (cj:CrownJewel)
MATCH (s:Host) WHERE s.compromised OR s.kind = 'internet'
MATCH p = (s)-[:CONNECTS_TO*1..8]->(cj)
WHERE ALL(r IN relationships(p) WHERE NOT coalesce(r.blocked, false))
  AND ALL(h IN nodes(p) WHERE NOT h.isolated AND NOT h.honeypot)
  AND ALL(h IN nodes(p)[1..] WHERE
        h.compromised
     OR EXISTS { (h)-[:HAS_VULN]->(v:Vuln) WHERE NOT v.patched }
     OR EXISTS { (c:Credential)-[:GRANTS]->(h) WHERE c.stolen AND NOT c.rotated })
RETURN [h IN nodes(p) | h.id] AS ids
ORDER BY length(p) ASC
LIMIT 1
"""

SET_HOST = "MATCH (h:Host {id: $id}) SET h += $props"
SET_VULN = "MATCH (v:Vuln {id: $id}) SET v += $props"
SET_CRED = "MATCH (c:Credential {id: $id}) SET c += $props"
SET_EDGE_BLOCKED = """
MATCH (:Host {id: $src})-[e:CONNECTS_TO]->(:Host {id: $dst})
SET e.blocked = $blocked
"""

ADD_HONEYPOT = """
MATCH (near:Host {id: $near})
MERGE (h:Host {id: $id})
SET h += $props
MERGE (near)-[:CONNECTS_TO {port: 443, protocol: 'tcp', blocked: false}]->(h)
"""

LOG_TURN = """
CREATE (t:Turn {n: $n, round: $round, side: $side, action: $action, args: $args,
                success: $success, narration: $narration, thought: $thought,
                fallback: $fallback, ts: datetime()})
WITH t
OPTIONAL MATCH (h:Host {id: $target})
FOREACH (_ IN CASE WHEN h IS NULL THEN [] ELSE [1] END | CREATE (t)-[:AFFECTED]->(h))
"""

FETCH_TURNS = "MATCH (t:Turn) RETURN t ORDER BY t.n"
