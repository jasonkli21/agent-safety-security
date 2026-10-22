"""Adversarial local graph contracts, exact path ceilings and atomic state transitions."""

import asyncio
from datetime import timedelta

import pytest
from pydantic import ValidationError
from test_runtime_policy import NOW, contract_with
from test_runtime_state import Broker, tool

from agentsec.compiler import compile_contract
from agentsec.domain.events import GraphEventPayload, ToolDispatchedPayload, ToolRequestedPayload
from agentsec.domain.graph import AgentNode, DelegationEdge, GraphSnapshot
from agentsec.domain.identity import Delegation, PrincipalRef, TaskScope
from agentsec.domain.serialization import canonical_json, content_digest
from agentsec.domain.taxonomy import DataLabel, PrincipalType
from agentsec.evidence.memory import InMemoryEventSink
from agentsec.identity.static import StaticIdentityProvider
from agentsec.multi_agent.messaging import MessageRoute
from agentsec.multi_agent.session import MultiAgentSession
from agentsec.runtime.events import RuntimeEvents
from agentsec.runtime.models import RuntimeFailure, ToolResponse

READ, WRITE, MESSAGE = "web.search", "filesystem.write", "agent.message.send"
CAPS = frozenset({READ, WRITE, MESSAGE})
USER = PrincipalRef(principal_id="user", principal_type=PrincipalType.USER)


def setup(
    *,
    parent_decision="ALLOW",
    budget=20,
    cap=3,
    broker=None,
    sibling=False,
    data=None,
    providers=None,
    now=None,
    resources=None,
    root_runtime=None,
    root_timeout=120,
):
    now = now or [NOW]
    parents = {"a": None, "b": "a", "c": "a" if sibling else "b"}
    principals = {
        n: PrincipalRef(principal_id=n, principal_type=PrincipalType.AGENT) for n in parents
    }
    contracts, nodes, edges = {}, [], []
    for n, parent in parents.items():
        c = contract_with(
            budgets={
                "max_tool_calls": budget if n == "a" else 20,
                "max_delegated_agents": cap,
                "max_runtime_seconds": root_runtime if n == "a" else None,
            },
            approvals={"default_timeout_seconds": root_timeout if n == "a" else 120},
            task_scope={"task_id": "task", "description": "test"},
            tools={
                "rules": [
                    {
                        "rule_id": "read",
                        "capability": READ,
                        "decision": parent_decision if n == "a" else "ALLOW",
                    },
                    {
                        "rule_id": "write",
                        "capability": WRITE,
                        "decision": "DENY" if n == "a" else "ALLOW",
                    },
                    {"rule_id": "message", "capability": MESSAGE, "decision": "ALLOW"},
                ]
            },
            data=data or {"rules": []},
        )
        c = c.model_copy(
            update={
                "metadata": c.metadata.model_copy(update={"contract_id": f"contract-{n}"}),
                "identity": c.identity.model_copy(
                    update={
                        "principal": principals[n],
                        "acts_on_behalf_of": principals[parent] if parent else USER,
                    }
                ),
                "agent": c.agent.model_copy(update={"agent_id": n}),
            }
        )
        contracts[n] = c
        nodes.append(
            AgentNode(
                node_id=n,
                principal=principals[n],
                plan_identity=compile_contract(c, multi_agent=True).identity,
            )
        )
        grant = Delegation(
            schema_version="0.1",
            delegation_id=f"grant-{n}",
            delegator=principals[parent] if parent else USER,
            delegate=principals[n],
            task_scope=TaskScope(
                task_id="task", description="grant", resource_scopes=resources if n == "a" else None
            ),
            capability_scope=CAPS,
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=300),
            parent_delegation_id=f"grant-{parent}" if parent else None,
        )
        edges.append(
            DelegationEdge(parent_id=parent, child_id=n, delegation_json=canonical_json(grant))
        )
    graph = GraphSnapshot(
        schema_version="0.1", generation=1, root=USER, nodes=tuple(nodes), edges=tuple(edges)
    )

    def clock():
        return now[0]

    session = MultiAgentSession(
        graph,
        contracts,
        providers or {n: StaticIdentityProvider(p) for n, p in principals.items()},
        broker or Broker(),
        clock=clock,
    )
    sinks, gateways = {}, {}
    for n in parents:
        sinks[n] = InMemoryEventSink()
        gateways[n] = session.activate(n, RuntimeEvents(sinks[n], clock))
    return session, gateways, sinks, contracts


async def call(gateway, capability=READ, *, resource=None, labels=frozenset(), destination="local"):
    descriptor = tool().model_copy(update={"capabilities": frozenset({capability})})

    async def dispatch(args):
        return ToolResponse(body={"ok": True}, success=True)

    return await gateway.call(
        descriptor,
        {},
        resource,
        dispatch,
        bound=True,
        output_data_labels=labels,
        data_destination=destination,
    )


def test_three_principal_chain_read_and_ancestor_deny():
    async def run():
        session, gateways, sinks, _ = setup()
        assert (await call(gateways["c"])).success
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await call(gateways["c"], WRITE)
        dispatched = [e for e in sinks["c"].events if isinstance(e.payload, ToolDispatchedPayload)]
        assert len(dispatched) == 1
        request = next(
            e.payload for e in sinks["c"].events if isinstance(e.payload, ToolRequestedPayload)
        )
        assert request.request.graph_binding.path == ("a", "b", "c")
        assert session.material.graph.digest == request.request.graph_binding.graph_digest

    asyncio.run(run())


def test_graph_permutation_alias_and_legacy_plan_identity():
    session, _, _, contracts = setup()
    graph = session.material.graph
    reverse = GraphSnapshot(
        schema_version="0.1",
        generation=1,
        root=USER,
        nodes=tuple(reversed(graph.nodes)),
        edges=tuple(reversed(graph.edges)),
    )
    assert graph.digest == reverse.digest
    edge = graph.edges[0]
    grant = edge.grant
    assert compile_contract(contracts["a"]).compiler_version == "phase6-v1"
    assert "budgets.max_delegated_agents" in compile_contract(contracts["a"]).gaps
    assert not compile_contract(contracts["a"], multi_agent=True).gaps
    assert grant.delegate == graph.nodes[0].principal


@pytest.mark.parametrize(
    "change", ["duplicate_node", "duplicate_edge", "parent", "cycle", "task", "version", "unknown"]
)
def test_invalid_graph(change):
    session, _, _, _ = setup()
    raw = session.material.graph.model_dump(mode="json")
    if change == "duplicate_node":
        raw["nodes"].append(raw["nodes"][0])
    if change == "duplicate_edge":
        raw["edges"].append(raw["edges"][0])
    if change == "parent":
        raw["edges"][1]["parent_id"] = "absent"
    if change in {"cycle", "task"}:
        import json

        grant = json.loads(raw["edges"][1]["delegation_json"])
        if change == "cycle":
            grant["parent_delegation_id"] = "grant-c"
        else:
            grant["task_scope"]["task_id"] = "other"
        raw["edges"][1]["delegation_json"] = canonical_json(grant)
    if change == "version":
        raw["schema_version"] = "9.0"
    if change == "unknown":
        raw["sender"] = "forged"
    with pytest.raises(ValidationError):
        GraphSnapshot.model_validate_json(canonical_json(raw))


def test_ancestor_approval_and_epoch_aba_rejection():
    async def run():
        entered, release = asyncio.Event(), asyncio.Event()

        class Waiting(Broker):
            calls = 0

            async def decide(self, request, presentation):
                self.calls += 1
                entered.set()
                await release.wait()
                return await super().decide(request, presentation)

        broker = Waiting()
        session, gateways, sinks, _ = setup(parent_decision="REQUIRE_APPROVAL", broker=broker)
        pending = asyncio.create_task(call(gateways["c"]))
        await entered.wait()
        assert not any(isinstance(e.payload, ToolDispatchedPayload) for e in sinks["c"].events)
        graph = session.material.graph
        session.replace_graph(graph.model_copy(update={"generation": 2}))
        session.replace_graph(graph.model_copy(update={"generation": 3}))
        release.set()
        with pytest.raises(RuntimeFailure, match="GRAPH_BINDING_STALE"):
            await pending
        assert broker.calls == 1
        assert not session._budgets._pending
        assert not session._budgets._used
        assert not any(isinstance(e.payload, ToolDispatchedPayload) for e in sinks["c"].events)
        assert (await call(gateways["c"])).success

    asyncio.run(run())


def test_parallel_sibling_shared_last_slot_and_cancellation():
    async def run():
        entered = asyncio.Event()

        class Waiting(Broker):
            async def decide(self, request, presentation):
                entered.set()
                await asyncio.Event().wait()

        session, gateways, _, _ = setup(
            parent_decision="REQUIRE_APPROVAL", budget=1, sibling=True, broker=Waiting()
        )
        pending = asyncio.create_task(call(gateways["b"]))
        await entered.wait()
        with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
            await call(gateways["c"])
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert not session._budgets._pending
        token = session._budgets.reserve(tool(), session.material.binding("c"), content_digest("a"))
        session._budgets.commit(token)
        session._budgets.refund(token)
        session._budgets.refund(token)
        assert session._budgets._used["a"] == [0, 0, 0]

    asyncio.run(run())


def test_evidence_failure_before_dispatch_compensates_exactly():
    async def run():
        session, gateways, sinks, _ = setup(budget=1)
        original = sinks["c"].append

        def fail(event):
            if isinstance(event.payload, ToolDispatchedPayload):
                raise OSError("secret")
            original(event)

        sinks["c"].append = fail
        with pytest.raises(RuntimeFailure, match="EVIDENCE_WRITE_FAILURE"):
            await call(gateways["c"])
        assert session._budgets._used["a"] == [0, 0, 0]
        assert not session._budgets._pending
        assert (await call(gateways["b"])).success

    asyncio.run(run())


def test_messages_monotonic_labels_and_receiver_evidence_before_release():
    async def run():
        session, gateways, sinks, _ = setup()
        await call(gateways["a"], labels=frozenset({DataLabel.SECRET, DataLabel.PII}))
        route = MessageRoute(session, "a", "b")
        assert (await route.send("untrusted secret body")).success
        assert session.receive("b") == ("untrusted secret body",)
        assert {DataLabel.SECRET, DataLabel.PII} <= set.union(
            set(), *(set(r.labels) for r in gateways["b"].provenance.snapshot())
        )
        second = MessageRoute(session, "b", "c")
        await second.send("relay")
        assert session.receive("c") == ("relay",)
        text = canonical_json(tuple(e for s in sinks.values() for e in s.events))
        assert "untrusted secret body" not in text
        imported = [
            e
            for e in sinks["b"].events
            if isinstance(e.payload, GraphEventPayload)
            and e.payload.operation == "MESSAGE_IMPORTED"
        ]
        assert len(imported) == 1
        with pytest.raises(RuntimeFailure, match="GRAPH_NONADJACENT_ROUTE"):
            MessageRoute(session, "a", "c")
        original = sinks["c"].append

        def fail(event):
            if (
                isinstance(event.payload, GraphEventPayload)
                and event.payload.operation == "MESSAGE_IMPORTED"
            ):
                raise OSError("sink")
            original(event)

        sinks["c"].append = fail
        previous = gateways["c"].provenance.snapshot()
        with pytest.raises(RuntimeFailure, match="UPSTREAM_FAILURE"):
            await second.send("must be withheld")
        assert session.receive("c") == ()
        assert gateways["c"].provenance.snapshot() == previous

    asyncio.run(run())


def test_expired_grandparent_and_finish_invalidate_child():
    async def run():
        now = [NOW]
        _session, gateways, _, _ = setup(now=now)
        now[0] += timedelta(seconds=300)
        with pytest.raises(RuntimeFailure, match="GRAPH_AUTHORITY_EXPIRED"):
            await call(gateways["c"])
        now[0] = NOW
        gateways["a"].finish()
        with pytest.raises(RuntimeFailure, match="GRAPH_ANCESTOR_INACTIVE"):
            await call(gateways["c"])

    asyncio.run(run())


def test_delegated_agent_cap_counts_all_descendants():
    with pytest.raises(RuntimeFailure, match="GRAPH_AGENT_CAP_EXCEEDED"):
        setup(cap=1)


def test_resource_grandparent_scope_and_empty_capability_deny():
    async def run():
        session, gateways, _, _ = setup(resources={READ: frozenset({"safe"})})
        assert (await call(gateways["c"], resource="safe")).success
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await call(gateways["c"], resource="other")
        graph = session.material.graph
        edge = graph.edges[0]
        grant = edge.grant.model_copy(update={"capability_scope": frozenset()})
        # The resource key is invalid with an empty capability ceiling.
        with pytest.raises(ValidationError):
            DelegationEdge(parent_id=None, child_id="a", delegation_json=canonical_json(grant))

    asyncio.run(run())


def test_offline_graph_reconstruction_and_material_blockers():
    from agentsec.multi_agent.conformance import graph_conformance
    from agentsec.multi_agent.replay import GraphReplayInput, replay_graph

    async def run():
        session, gateways, sinks, _ = setup()
        events = [event for n in ("a", "b", "c") for event in sinks[n].events]
        for sink in sinks.values():
            original = sink.append

            def collect(event, original=original):
                original(event)
                events.append(event)

            sink.append = collect
        assert (await call(gateways["c"])).success
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await call(gateways["c"], WRITE)
        for n in ("c", "b", "a"):
            gateways[n].finish()
        source = GraphReplayInput(
            schema_version="0.1",
            events=tuple(events),
            source_evidence_digest=content_digest(tuple(events)),
            material=session.material,
            tools=(tool(),),
        )
        result = replay_graph(source, candidate_graph=session.material.graph)
        assert result.blockers == frozenset()
        assert result.fidelity == "SECURITY_SEMANTIC"
        assert result.checked_requests == 2
        assert result.candidate_graph_comparison == "UNCHANGED"
        missing = replay_graph(source.model_copy(update={"material": None}))
        assert missing.blockers == {"MISSING_GRAPH_ANCESTOR_MATERIAL"}
        report = graph_conformance(session.material, NOW)
        assert not any(p.status == "FAIL" for p in report.probes)
        assert sum(p.status == "PASS" for p in report.probes) >= 15

    asyncio.run(run())


def test_data_deny_cannot_be_laundered_through_messages():
    async def run():
        session, gateways, sinks, _ = setup(
            data={
                "rules": [
                    {
                        "rule_id": "no-secret-peer",
                        "label": "SECRET",
                        "denied_destinations": ["agent:b"],
                    }
                ]
            }
        )
        await call(gateways["a"], labels=frozenset({DataLabel.SECRET}))
        route = MessageRoute(session, "a", "b")
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await route.send("try to label this PUBLIC")
        assert session.receive("b") == ()
        assert not any(
            isinstance(e.payload, ToolDispatchedPayload) and e.payload.tool_id == "message/a/b"
            for e in sinks["a"].events
        )

    asyncio.run(run())


def test_identity_wrong_provider_and_missing_provider_fail_before_activation():
    # Reconstruct the operator inputs, without reusing any asserted sender field.
    session, _, _, contracts = setup()
    graph = session.material.graph
    providers = {n: StaticIdentityProvider(USER) for n in contracts}
    with pytest.raises(ValidationError, match="GRAPH_PARTICIPANT_BINDING_INVALID"):
        MultiAgentSession(graph, contracts, providers, Broker(), clock=lambda: NOW)
    with pytest.raises(RuntimeFailure, match="GRAPH_CONFIGURATION_MISMATCH"):
        MultiAgentSession(graph, contracts, {}, Broker(), clock=lambda: NOW)


def test_direct_gateway_cannot_drop_guard_or_bind_foreign_plan():
    from agentsec.domain.taxonomy import EnforcementMode
    from agentsec.runtime.gateway import RuntimeGateway

    session, _, _, contracts = setup()
    with pytest.raises(RuntimeFailure, match="STALE_COMPILED_PLAN"):
        RuntimeGateway(
            contracts["c"],
            EnforcementMode.ENFORCE,
            RuntimeEvents(InMemoryEventSink(), lambda: NOW),
            Broker(),
            plan=session.material.participant("c").plan,
        )


def test_cross_thread_mutation_and_nonincreasing_generation_rejected():
    from concurrent.futures import ThreadPoolExecutor

    session, _, _, _ = setup()
    graph = session.material.graph
    with pytest.raises(RuntimeFailure, match="GRAPH_GENERATION_NOT_INCREASING"):
        session.replace_graph(graph)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(session.replace_graph, graph.model_copy(update={"generation": 2}))
        with pytest.raises(RuntimeFailure, match="GRAPH_CROSS_THREAD_UNSUPPORTED"):
            future.result()


def test_reentrant_evidence_revocation_is_checked_before_dispatcher_entry():
    async def run():
        session, gateways, sinks, _ = setup()
        original = sinks["c"].append

        def revoke(event):
            original(event)
            if isinstance(event.payload, ToolDispatchedPayload):
                session.revoke("a")

        sinks["c"].append = revoke
        effects = []

        async def dispatch(arguments):
            effects.append(True)
            return ToolResponse(body={}, success=True)

        with pytest.raises(RuntimeFailure, match="GRAPH_ANCESTOR_INACTIVE"):
            await gateways["c"].call(tool(), {}, None, dispatch, bound=True)
        assert effects == []
        assert session._budgets._used["a"] == [0, 0, 0]

    asyncio.run(run())


@pytest.mark.parametrize("ceiling", [frozenset(), frozenset({WRITE})])
def test_verified_ancestor_credential_ceiling_is_restrictive(ceiling):
    async def run():
        old, _, _, contracts = setup()
        graph = old.material.graph
        providers = {
            n: StaticIdentityProvider(c.identity.principal, ceiling if n == "a" else None)
            for n, c in contracts.items()
        }
        session = MultiAgentSession(graph, contracts, providers, Broker(), clock=lambda: NOW)
        gateways = {n: session.activate(n, RuntimeEvents(InMemoryEventSink())) for n in contracts}
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await call(gateways["c"])

    asyncio.run(run())


def test_signed_jwt_participant_is_verified_and_unbound_proof_fails():
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from agentsec.adapters.identity.jwt import JwtIdentityProvider
    from agentsec.identity.config import JwtIdentityConfig
    from agentsec.identity.ports import IdentityError

    session, _, _, contracts = setup()
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    cfg = JwtIdentityConfig.model_validate_json(
        canonical_json(
            {
                "provider": "signed_jwt",
                "issuer": "issuer",
                "audience": "graph",
                "keys": [{"kid": "key", "algorithm": "RS256", "public_key_pem": public}],
                "subjects": [
                    {"subject": "worker-c", "principal": contracts["c"].identity.principal}
                ],
                "scope_mapping": {"read": READ},
            }
        )
    )
    providers = {n: StaticIdentityProvider(c.identity.principal) for n, c in contracts.items()}
    providers["c"] = JwtIdentityProvider(cfg)
    claims = {
        "iss": "issuer",
        "aud": "graph",
        "sub": "worker-c",
        "scope": "read",
        "nbf": int(NOW.timestamp()) - 1,
        "exp": int(NOW.timestamp()) + 20,
    }
    token = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "key"})
    verified = MultiAgentSession(
        session.material.graph,
        contracts,
        providers,
        Broker(),
        clock=lambda: NOW,
        credentials={"c": token},
    )
    assert verified.material.participant("c").credential.assurance == "SIGNED_JWT"
    assert token not in canonical_json(verified.material)
    with pytest.raises(IdentityError):
        MultiAgentSession(session.material.graph, contracts, providers, Broker(), clock=lambda: NOW)
    with pytest.raises(IdentityError):
        MultiAgentSession(
            session.material.graph,
            contracts,
            providers,
            Broker(),
            clock=lambda: NOW,
            credentials={"c": jwt.encode(claims, "", algorithm="none")},
        )


def test_ancestor_only_data_rule_classification_cannot_be_omitted():
    async def run():
        old, _, _, contracts = setup(
            data={
                "rules": [
                    {"rule_id": "secret", "label": "SECRET", "denied_destinations": ["outside"]}
                ]
            }
        )
        for node in ("b", "c"):
            contracts[node] = contracts[node].model_copy(
                update={"data": contracts[node].data.model_copy(update={"rules": ()})}
            )
        graph = old.material.graph.model_copy(
            update={
                "nodes": tuple(
                    node.model_copy(
                        update={
                            "plan_identity": compile_contract(
                                contracts[node.node_id], multi_agent=True
                            ).identity
                        }
                    )
                    for node in old.material.graph.nodes
                )
            }
        )
        session = MultiAgentSession(
            graph,
            contracts,
            {n: StaticIdentityProvider(c.identity.principal) for n, c in contracts.items()},
            Broker(),
            clock=lambda: NOW,
        )
        gateways = {n: session.activate(n, RuntimeEvents(InMemoryEventSink())) for n in contracts}

        async def effect(args):
            pytest.fail("unclassified ancestor source dispatched")

        with pytest.raises(RuntimeFailure, match="GRAPH_SOURCE_CLASSIFICATION_REQUIRED"):
            await gateways["c"].call(tool(), {}, None, effect, bound=True, data_destination="local")

    asyncio.run(run())


def test_graph_bundle_and_incident_promotion_remain_honest_draft():
    from agentsec.domain.replay import RegressionState
    from agentsec.domain.scenarios import ToolNotCalled
    from agentsec.incident.classify import classify
    from agentsec.incident.promote import promote
    from agentsec.replay.bundle import create_bundle
    from agentsec.replay.engine import replay

    async def run():
        _, gateways, sinks, contracts = setup()
        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await call(gateways["c"], WRITE)
        gateways["c"].finish()
        bundle = create_bundle(
            tuple(sinks["c"].events),
            contracts["c"],
            tools=(tool().model_copy(update={"capabilities": frozenset({WRITE})}),),
            expectations=(ToolNotCalled(type="TOOL_NOT_CALLED", tool_id="tool"),),
        )
        assert "GRAPH_SESSION_REPLAY_REQUIRED" in replay(bundle).assessment.blockers
        case = promote(bundle, classify(bundle))
        assert case.state == RegressionState.DRAFT
        assert case.source_evidence_digest == bundle.source_evidence_digest
        assert case.program is None

    asyncio.run(run())


def test_message_replay_checks_causality_labels_and_duplicate_import():
    from agentsec.multi_agent.replay import GraphReplayInput, replay_graph

    async def run():
        session, gateways, sinks, _ = setup()
        events = [e for node in ("a", "b", "c") for e in sinks[node].events]
        for sink in sinks.values():
            original = sink.append

            def collect(event, original=original):
                original(event)
                events.append(event)

            sink.append = collect
        await call(gateways["a"], labels=frozenset({DataLabel.SECRET}))
        route = MessageRoute(session, "a", "b")
        await route.send("never persisted")
        for n in ("c", "b", "a"):
            gateways[n].finish()
        source = GraphReplayInput(
            schema_version="0.1",
            events=tuple(events),
            material=session.material,
            source_evidence_digest=content_digest(tuple(events)),
            tools=(tool(), route.tool.descriptor),
        )
        result = replay_graph(source)
        assert result.blockers == frozenset()
        assert result.checked_deliveries == 1
        changed = []
        for event in events:
            if (
                isinstance(event.payload, GraphEventPayload)
                and event.payload.operation == "MESSAGE_IMPORTED"
            ):
                p = event.payload
                event = event.model_copy(
                    update={
                        "payload": p.model_copy(
                            update={
                                "artifact": p.artifact.model_copy(
                                    update={"labels": frozenset({DataLabel.PUBLIC})}
                                )
                            }
                        )
                    }
                )
            changed.append(event)
        forged = source.model_copy(
            update={
                "events": tuple(changed),
                "source_evidence_digest": content_digest(tuple(changed)),
            }
        )
        assert "GRAPH_MESSAGE_LABEL_OR_CONTENT_MISMATCH" in replay_graph(forged).blockers

    asyncio.run(run())


@pytest.mark.parametrize(
    "violation", ["self", "expiry", "root", "coerced_generation", "grant_size"]
)
def test_graph_strict_windows_principals_and_bounds(violation):
    import json

    session, _, _, _ = setup()
    raw = session.material.graph.model_dump(mode="json")
    if violation == "root":
        raw["root"]["principal_type"] = "AGENT"
    if violation == "coerced_generation":
        raw["generation"] = "1"
    if violation == "self":
        raw["edges"][1]["parent_id"] = "b"
    if violation in {"expiry", "grant_size"}:
        grant = json.loads(raw["edges"][1]["delegation_json"])
        if violation == "expiry":
            grant["expires_at"] = (NOW + timedelta(days=1)).isoformat()
        else:
            grant["task_scope"]["resource_scopes"] = {READ: ["é" * 5000]}
        raw["edges"][1]["delegation_json"] = canonical_json(grant)
    with pytest.raises(ValidationError):
        GraphSnapshot.model_validate_json(canonical_json(raw))


def test_empty_grant_and_resource_sets_deny_all_without_erasing_ancestor():
    async def run():
        for kind in ("caps", "resources"):
            session, gateways, _, _ = setup()
            graph = session.material.graph
            edge = graph.edges[0]
            grant = edge.grant
            if kind == "caps":
                grant = grant.model_copy(update={"capability_scope": frozenset()})
            else:
                grant = grant.model_copy(
                    update={
                        "task_scope": grant.task_scope.model_copy(
                            update={"resource_scopes": {READ: frozenset()}}
                        )
                    }
                )
            edges = (
                edge.model_copy(update={"delegation_json": canonical_json(grant)}),
                *graph.edges[1:],
            )
            session.replace_graph(graph.model_copy(update={"generation": 2, "edges": edges}))
            with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
                await call(gateways["c"], resource="anything")

    asyncio.run(run())


def test_retirement_never_resets_agent_admission_history():
    session, gateways, _, _ = setup(cap=2)
    gateways["c"].finish()
    assert session._budgets._admitted["a"] == {"b", "c"}
    with pytest.raises(RuntimeFailure, match="GRAPH_NODE_ALREADY_ACTIVATED"):
        session.activate("c", RuntimeEvents(InMemoryEventSink()))
    assert session._budgets._admitted["a"] == {"b", "c"}


def test_possibly_effectful_dispatch_is_never_refunded():
    async def run():
        session, gateways, _, _ = setup(budget=1)
        effects = []

        async def dispatch(args):
            effects.append(True)
            raise RuntimeError("after effect")

        with pytest.raises(RuntimeFailure, match="UPSTREAM_FAILURE"):
            await gateways["c"].call(tool(), {}, None, dispatch, bound=True)
        assert effects == [True]
        assert session._budgets._used["a"] == [1, 0, 0]
        with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
            await call(gateways["b"])

    asyncio.run(run())


def test_graph_mode_and_noncritical_evidence_are_rejected():
    from agentsec.domain.taxonomy import EnforcementMode
    from agentsec.multi_agent.session import SessionGuard
    from agentsec.runtime.gateway import RuntimeGateway

    session, _, _, contracts = setup()
    guard = SessionGuard(session, "c")
    for mode, required in (
        (EnforcementMode.SHADOW, True),
        (EnforcementMode.DISABLED, True),
        (EnforcementMode.ENFORCE, False),
    ):
        with pytest.raises(RuntimeFailure, match="GRAPH_MODE_UNSUPPORTED"):
            RuntimeGateway(
                contracts["c"],
                mode,
                RuntimeEvents(InMemoryEventSink(), required=required),
                Broker(),
                graph_guard=guard,
            )


def test_graph_final_trust_drift_and_provider_rebind_cannot_bypass_pins():
    from agentsec.adapters.native import native_binding, protect_native
    from agentsec.adapters.providers import ProviderTools
    from agentsec.runtime.bindings import ProtectedTool
    from agentsec.supply_chain.guard import TrustGuard
    from agentsec.supply_chain.models import TrustLock, TrustPin
    from agentsec.supply_chain.registration import inspect_protected

    async def run():
        old, _, _, contracts = setup(parent_decision="REQUIRE_APPROVAL")
        metadata = ProtectedTool(
            schema_version="0.1",
            descriptor=tool(),
            execution_binding=native_binding("read", "1"),
            output_data_labels=frozenset(),
        )
        candidate = inspect_protected(metadata)
        lock = TrustLock(
            schema_version="0.1",
            status="REVIEWED",
            generation="one",
            pins=(
                TrustPin(
                    schema_version="0.1",
                    candidate_id=candidate.candidate_id,
                    fingerprint=candidate.fingerprint,
                ),
            ),
        )
        guard = TrustGuard(lock)
        entered, release = asyncio.Event(), asyncio.Event()

        class Waiting(Broker):
            async def decide(self, request, presentation):
                entered.set()
                await release.wait()
                return await super().decide(request, presentation)

        session = MultiAgentSession(
            old.material.graph,
            contracts,
            {n: StaticIdentityProvider(c.identity.principal) for n, c in contracts.items()},
            Waiting(),
            clock=lambda: NOW,
        )
        for n in ("a", "b"):
            session.activate(n, RuntimeEvents(InMemoryEventSink()))
        gateway = session.activate("c", RuntimeEvents(InMemoryEventSink()), trust_guard=guard)

        async def effect(args):
            pytest.fail("trust drift dispatched")

        protected = protect_native(gateway, metadata, effect)
        with pytest.raises(RuntimeFailure, match="TRUST_ADMISSION_REJECTED"):
            ProviderTools("openai", (protected,))
        pending = asyncio.create_task(protected.invoke({}))
        await entered.wait()
        guard.replace_lock(lock.model_copy(update={"generation": "two"}))
        release.set()
        with pytest.raises(RuntimeFailure, match="TRUST_"):
            await pending
        assert not session._budgets._pending
        assert not session._budgets._used

    asyncio.run(run())


def test_slow_critical_evidence_cannot_cross_ancestor_runtime_deadline():
    async def run():
        session, gateways, sinks, _ = setup(root_runtime=1)
        elapsed = [0.0]
        session._budgets._started = 0
        session._budgets._clock = lambda: elapsed[0]
        original = sinks["c"].append

        def slow(event):
            original(event)
            if isinstance(event.payload, ToolDispatchedPayload):
                elapsed[0] = 1.0

        sinks["c"].append = slow
        effects = []

        async def dispatch(args):
            effects.append(True)
            return ToolResponse(body={}, success=True)

        with pytest.raises(RuntimeFailure, match="BUDGET_EXCEEDED"):
            await gateways["c"].call(tool(), {}, None, dispatch, bound=True)
        assert not effects
        assert session._budgets._used["a"] == [0, 0, 0]

    asyncio.run(run())


def test_strictest_ancestor_timeout_releases_shared_reservation():
    async def run():
        class Waiting(Broker):
            async def decide(self, request, presentation):
                assert (request.expires_at - request.created_at).total_seconds() == 1
                await asyncio.Event().wait()

        session, gateways, _, _ = setup(
            parent_decision="REQUIRE_APPROVAL", broker=Waiting(), root_timeout=1
        )
        with pytest.raises(RuntimeFailure, match="APPROVAL_TIMEOUT"):
            await call(gateways["c"])
        assert not session._budgets._pending
        assert not session._budgets._used

    asyncio.run(run())


def test_parent_credential_expires_during_awaited_approval():
    async def run():
        now = [NOW]
        entered, release = asyncio.Event(), asyncio.Event()

        class Finite(StaticIdentityProvider):
            def verify(self, credential, now):
                return (
                    super()
                    .verify(credential, now)
                    .model_copy(update={"expires_at": NOW + timedelta(seconds=5)})
                )

        providers = {
            n: (Finite if n == "a" else StaticIdentityProvider)(
                PrincipalRef(principal_id=n, principal_type=PrincipalType.AGENT)
            )
            for n in ("a", "b", "c")
        }

        class Waiting(Broker):
            async def decide(self, request, presentation):
                entered.set()
                await release.wait()
                return await super().decide(request, presentation)

        session, gateways, sinks, _ = setup(
            parent_decision="REQUIRE_APPROVAL", broker=Waiting(), providers=providers, now=now
        )
        pending = asyncio.create_task(call(gateways["c"]))
        await entered.wait()
        now[0] += timedelta(seconds=6)
        release.set()
        with pytest.raises(RuntimeFailure, match="GRAPH_AUTHORITY_EXPIRED"):
            await pending
        assert not any(isinstance(e.payload, ToolDispatchedPayload) for e in sinks["c"].events)
        assert not session._budgets._pending

    asyncio.run(run())


def test_graph_incident_promotes_minimal_manifest_and_runs_explicit_assertion():
    from agentsec.domain.scenarios import ToolNotCalled
    from agentsec.incident.classify import classify
    from agentsec.multi_agent.regression import promote_graph, run_graph_case
    from agentsec.multi_agent.replay import GraphReplayInput
    from agentsec.replay.bundle import create_bundle

    async def run():
        session, gateways, sinks, contracts = setup()
        events = [e for n in ("a", "b", "c") for e in sinks[n].events]
        for sink in sinks.values():
            original = sink.append

            def collect(event, original=original):
                original(event)
                events.append(event)

            sink.append = collect
        await call(gateways["c"])
        descriptor = tool().model_copy(
            update={"capabilities": frozenset({WRITE}), "tool_id": "write"}
        )

        async def forbidden(args):
            pytest.fail("ancestor-denied write dispatched")

        with pytest.raises(RuntimeFailure, match="POLICY_DENIED"):
            await gateways["c"].call(descriptor, {}, None, forbidden, bound=True)
        for n in ("c", "b", "a"):
            gateways[n].finish()
        bundle = create_bundle(
            tuple(sinks["c"].events),
            contracts["c"],
            tools=(tool(), descriptor),
            expectations=(ToolNotCalled(type="TOOL_NOT_CALLED", tool_id="write"),),
        )
        source = GraphReplayInput(
            schema_version="0.1",
            events=tuple(events),
            material=session.material,
            source_evidence_digest=content_digest(tuple(events)),
            tools=(tool(), descriptor),
        )
        case = promote_graph(bundle, classify(bundle), source, "c")
        assert case.state == "ACTIVE"
        assert run_graph_case(case, source).status == "PASS"
        assert "delegation_json" not in canonical_json(case)
        assert "credential" not in canonical_json(case)
        missing = source.model_copy(update={"material": None})
        assert run_graph_case(case, missing).status == "BLOCKED"
        # A nontrivial stricter expectation fails over an actually dispatched read.
        changed = case.model_copy(
            update={"expectations": (ToolNotCalled(type="TOOL_NOT_CALLED", tool_id="tool"),)}
        )
        assert run_graph_case(changed, source).status == "FAIL"
        unknown = case.model_copy(update={"node_id": "unknown"})
        assert "GRAPH_RUN_BINDING_MISSING" in run_graph_case(unknown, source).blockers

    asyncio.run(run())


@pytest.mark.parametrize("shape", ["depth", "fanout"])
def test_graph_depth_and_fanout_are_hard_limits(shape):
    session, _, _, _ = setup()
    original = session.material.graph
    nodes = [original.nodes[0]]
    edges = [original.edges[0]]
    for i in range(1, 10):
        name = f"node-{i}"
        parent = edges[-1].child_id if shape == "depth" else "a"
        parent_edge = next(e for e in edges if e.child_id == parent)
        principal = PrincipalRef(principal_id=name, principal_type=PrincipalType.AGENT)
        nodes.append(
            AgentNode(
                node_id=name, principal=principal, plan_identity=original.nodes[0].plan_identity
            )
        )
        grant = original.edges[0].grant.model_copy(
            update={
                "delegation_id": f"grant-{i}",
                "delegate": principal,
                "delegator": next(n.principal for n in nodes if n.node_id == parent),
                "parent_delegation_id": parent_edge.grant.delegation_id,
            }
        )
        edges.append(
            DelegationEdge(parent_id=parent, child_id=name, delegation_json=canonical_json(grant))
        )
    with pytest.raises(
        ValidationError, match="GRAPH_DEPTH_LIMIT" if shape == "depth" else "GRAPH_FANOUT_LIMIT"
    ):
        GraphSnapshot(
            schema_version="0.1", generation=1, root=USER, nodes=tuple(nodes), edges=tuple(edges)
        )
