CONSTRAINTS = [
    "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
    "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT cred_id IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vuln) REQUIRE v.id IS UNIQUE",
    "CREATE CONSTRAINT turn_n IF NOT EXISTS FOR (t:Turn) REQUIRE t.n IS UNIQUE",
]


def apply_constraints(run) -> None:
    for c in CONSTRAINTS:
        run(c)
