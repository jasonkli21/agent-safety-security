# Local graph slice

Run from the repository root:

```bash
.venv/bin/python examples/multi_agent/local_session.py
.venv/bin/agentsec graph validate --config examples/multi_agent/graph.json
.venv/bin/agentsec graph replay --config examples/multi_agent/replay.json
.venv/bin/agentsec graph regression --case examples/multi_agent/regression.json --source examples/multi_agent/replay.json
```

`local_session.py` builds three independent principals/contracts from `contract-a.yaml`, with
explicit USER → A → B → C grants and local trusted static providers. It uses a fixed fixture
clock, synthetic native tools, real gateway approvals and an in-memory route. It demonstrates
read success, inherited write denial, SECRET label relay, shared budgets, sibling rejection
and graph replacement during awaited approval. No model, network, real filesystem action or
remote authentication is performed.

`graph.json` is structural operator configuration. `replay.json` is a separately reviewed public
synthetic source: graph/plans, safe credential summaries, content-free events and tool metadata.
It contains no JWT or tool/message body. `regression.json` is a minimal incident-derived manifest
with an explicit no-write assertion, source commitments and no embedded protected authority.
Real application source material must remain access controlled. Replay proves recorded structured
semantics at recorded times, not source authenticity or external effects.
