# Local team reference demo

From the repository root with Python 3.12+:

```bash
python -m pip install -e '.[dev,control-plane]'
python examples/team/demo.py
```

This uses an in-process HTTP client, temporary SQLite database and publicly known synthetic
Ed25519 test issuer. **Never trust this issuer/key for real users.** It deliberately demonstrates
UNKNOWN posture, unverified policy alignment and DRAFT regression coverage. A reported revision
label is only a claim; first-party runtime projections remain incomplete and cannot create a green
posture by themselves. The existing three-agent example runs after the team store is closed. No
listener, production token, external network, real IdP or cloud is used.
Default CI runs the same fixture without credentials; sending results to an actual service must
be a separately configured opt-in reporter job. There is no default outbound reporting.

For operator-managed loopback service use `agentsec team init DB CONFIG OWNER ORG`, then
`agentsec team provision DB BINDING` for each externally issued subject. JSON files conform to
the generated team-config and team-binding schemas. Config contains only public Ed25519 keys;
use a private protected file path for real config and database. Init checks that the owner is a
HUMAN bound to a configured issuer before creating storage and removes only its own new database
if bootstrap fails. Reopening a restored DB checks POSIX ownership and private modes on the DB and
existing WAL/SHM files; repair a copy while stopped. Existing database reopen is unsupported on
Windows because ACL checks are not implemented. An OWNER membership can then
provision roles/enrollment through authenticated API calls. Tokens are issued by your external
IdP with exact pinned `iss`, single-string `aud`, mapped `sub`, `nbf`, `exp`, `alg=EdDSA` and pinned
`kid`. Provision one binding per real human. JWT roles and org claims have no authority.

```bash
agentsec team serve DB CONFIG                       # 127.0.0.1:8765
agentsec team posture DB CONFIG PROTECTED_TOKEN ORG  # JSON/text dashboard
```

Credentials must be owned by the current uid, regular non-symlink files with no group/world
permissions (the existing bounded credential reader). `serve` refuses nonloopback bindings and
does not trust forwarded headers. These commands do not deploy or configure a TLS proxy.

All paths below start with `/v1/orgs/{org}/`; JSON requests accept the corresponding strict
`team-v1` model, omit no required fields, and reject unknown fields. Authorization is Bearer JWT;
there is no unauthenticated discovery. Responses are JSON with `Cache-Control: no-store`.

| Endpoint | Method / body | Role |
| --- | --- | --- |
| members | GET; POST Member | read / OWNER |
| agents | GET; POST Agent | read / OWNER |
| reporters | GET; POST Reporter | read / OWNER |
| revisions | GET; POST RevisionInput with explicit upload_source=true | read / EDITOR or OWNER |
| revisions/{revision} | GET Revision including computed diff/conformance/coverage | read |
| revisions/{revision}/source | GET exact opt-in source | read |
| revisions/{revision}/transitions | POST Transition with expected_version | action-specific |
| reports | GET receipts; POST Metadata | read / bound REPORTER |
| own-status | GET enrolled Agent | bound REPORTER |
| posture / alerts | GET Posture / deduplicated advisory flags | read |
| audit | GET governance audit | read |
| metadata-purge | POST empty TeamModel | OWNER |

Collections accept `offset=0..10000` and `limit=1..100`. Mutations return updated objects; member,
agent and reporter `expected_version` is the current CAS generation. New enrollment requires 0.
Revision versions start at 1; submit expects 1, approve 2, publish 3. Transition retries bind exact
actor/action/expected version/content; use GET to inspect current state after a historical retry.
Revision create uses a new ID and the current publication base_generation (initially 0). The
publisher advances this generation; a sibling draft reviewed against an old generation must be
recreated. Rejection/withdrawal keeps immutable history; it never edits source bytes.

Review acknowledgements are individual fields for initial policy, semantic expansion and gaps,
plus a finite review_reason. Independent verified human review is mandatory. Only an active
OWNER publishes and a reviewer must retain review permission at publication. Team approval is
never a runtime approval. `verify_fetch` verifies source/compiler identities against explicitly
expected metadata without writing local config. No remote client/pin/automatic rollout is included.

Retention purge removes expired receipts only in the selected org. Idempotency tombstones and
governance audit survive. The 1,000 lifetime record ceiling also bounds tombstones and transition
retry records; reaching it fails closed and requires a future reviewed archival/migration design,
not deletion/reuse of IDs. This reference is for bounded demonstrations, not a long-running fleet.
