# ROUND 6 — Evidence-driven collaboration decision

Date: 2026-11-08

## Decision

Keep the CityFlow traffic incident platform as the current experimental vehicle. Do not treat the static nine-candidate regression as evidence that multi-agent collaboration is necessary. Stop using unconditional all-to-all peer review as the default architecture.

The next task must introduce a legitimate, observable state change after initial analysis, require invalidation of stale plans, and independently verify the resulting vehicle trajectory and network constraints. All baselines must receive identical observations, tools, budgets and resource limits.

## Round 5 measured evidence

Source run: GitHub Actions `42470993563`, job `128701451953`, artifact `aios-collaboration-pilot-evidence` (ID `13614438328`).

| Mode | Task wall seconds | Model requests | Prompt tokens | Completion tokens | Outcome |
|---|---:|---:|---:|---:|---|
| Single | 178.794 | 5 | 6,229 | 99 | Feasible, objective-optimal (tie), replay identical |
| Parallel role team with peer review | 965.128 | 9 | 14,963 | 822 | Same business outcome |
| Parallel role team without peer review | 660.337 | 5 | 7,093 | 441 | Same business outcome |
| Serial role team | incomplete | one complete request | partial | partial | Outer shared 2,100-second deadline terminated the batch; no valid serial timing |

Each complete mode selected a plan with 505 simulated seconds, mean queue 90.8116667, and +4.938081% queue change against the baseline, within the predeclared 5% cap. `r1-task` and `r1-bounded` are objective ties; the previous ID-only audit flag was erroneous and has been superseded in independent audit, while original records remain immutable.

Parallel team / single task time ratio: about 5.398. No-feedback team / single: about 3.692. One run per mode on one already-solved development case; these are not general performance estimates.

Backend logs show maximum four in-flight model HTTP requests in parallel modes. On the shared CPU runner, those requests each took roughly 497–505 seconds in the first phase. This indicates severe contention/context overhead in this environment; it is not transferable to the user's RTX 4090.

## Collaboration audit

The peer-request protocol was malformed:
- Event, signal and route roles all requested network review.
- Network's answer map used `network` as the key rather than the original requester, so request/reply association was wrong.
- Candidate under review and candidate recommended for execution shared one field.
- Requesters were not called again to consume the reply and issue a revised artifact.
- No-feedback mode reached the same decision and outcome.

Therefore this run does not establish three valid bidirectional pairs, autonomous task allocation, or causal benefit from feedback.

## Event-triggered message protocol proposal (not yet implemented)

Every artifact must have:
- `artifact_id`, `agent_type`, `task_id`, `environment_version`, `evidence_refs`
- `subject_candidate_id` (what is being reviewed)
- `recommended_action_id` (what is proposed; nullable)
- `finding`, `constraints_checked`, `uncertainties`

Every request must have:
- `request_id`, `from_agent`, `to_agent`, `subject_artifact_id`
- `question`, `evidence_refs`, `expected_environment_version`

Every reply must have:
- `reply_to_request_id`, `from_agent`, `to_agent`
- `answer`, `supporting_evidence_refs`, `limitations`, `recommended_change`

A reply is not counted as a bidirectional interaction until the original requester is invoked again and emits a new artifact with `revision_of` pointing to the prior artifact. If no revision is warranted, the requester must emit an evidence-backed no-change decision. A static echo or a message count does not qualify.

Only trigger peer review when machine-checkable conflicts exist: stale environment version, route/signal incompatibility, network constraint violation, command acknowledgement inconsistent with observed state, or an execution failure. If there is no real conflict, do not manufacture communication.

Before execution, verify all referenced artifacts are current. After execution, inspect actual simulation state and vehicle trajectory; tool success is not task success.

## Next falsifiable experiment

Create a frozen dynamic-event task:
1. Initial event and shared observation are released to all methods.
2. Independent professional analyses start from the same environment version.
3. After a predeclared simulation time, a second observable event changes a route/control availability or invalidates a plan.
4. All methods receive the same event update and tools.
5. A plan tied to the old version must be rejected; the system must replan and verify destination, trajectory and network constraints.

Compare:
- deterministic planner / rules,
- fully equipped single 8B agent (including parallel tool use),
- event-triggered heterogeneous team serial,
- event-triggered heterogeneous team parallel,
- team without peer feedback.

Use equal independent per-mode deadlines, balanced/randomized run order, repeated seeds and held-out event locations. Count full task wall time including inference, queueing, communication, tool calls, retries and verification. Keep candidate/tool budgets equal. If the deterministic planner or strong single agent solves all held-out cases, do not claim multi-agent necessity.

## Status

Real Qwen3-8B + AIOS/Cerebrum compatibility path + native traffic tool loop: demonstrated on CPU hosted runner.

Actual heterogeneous team benefit: not demonstrated.

Three causal bidirectional interactions: not demonstrated.

Autonomous dynamic task allocation: not demonstrated.

20% full-task parallel speedup: not demonstrated.

User RTX 4090 performance: not measured.

No independent external subagent launch interface was available in this session. The prior four role contexts were separate calls to the same Qwen3-8B, not four independent research agents. No real road infrastructure was controlled.
