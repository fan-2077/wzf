# ROUND 7 — Dynamic event and route replanning evidence

Date: 2026-11-08

## Scope and status

AI-assisted feasibility work only. All runs used the pinned public CityFlow simulator and public CoLLMLight Hangzhou 4x4 traffic data on GitHub-hosted CPU runners. No real traffic infrastructure was controlled. No LLM or multi-agent participated in the dynamic event probe. The test is a deterministic environment/plan-invalidation experiment, not proof of multi-agent necessity, generalization, or contest speedup.

## Important earlier failures retained

1. At event time 900, CityFlow rejected route changes because the vehicle was already in the intersection/inside its lane transition.
2. At time 850, the target vehicle did not expose a suitable future controlled movement in the current route snapshot.
3. At time 880, and again at 705, road-level BFS generated a path that was graph-connected but not lane-feasible; CityFlow's Router expanded anchors through existing roads and returned a different route.
4. After constraining the first move to a lane-feasible movement, the reroute executed and trajectory matched the requested path. The first run had only a 900-second post-event horizon; the vehicle had reached the destination road but had not exited. The horizon was extended to 3000 seconds.
5. A read-only CityFlow phase observer was added to the build. It exposes the actual internal phase and does not alter traffic dynamics.

## Successful dynamic scenario

GitHub Actions run: `42494790221`  
Commit: `4d94fc7517d81cbf9951352840f78d1f37640f53`  
Artifact: `dynamic-traffic-event-evidence`, ID `13623470602`

Initial plan at simulation time 700:
- Vehicle: `flow_1457_0`
- Original route: `road_3_2_2 → road_2_2_2 → road_1_2_1 → road_1_3_1 → road_1_4_0 → road_2_4_0 → road_3_4_3 → road_3_3_3`
- Destination: `road_3_3_3`

At time 705, a second signal-controller fault is injected at `intersection_1_3`, holding phase 1 until time 1005. The original movement `road_1_2_1 → road_1_3_1` requires phase 2, so the pre-event plan is stale.

The reroute preserves the current lane's first movement and changes the later route:
- New route: `road_3_2_2 → road_2_2_2 → road_1_2_1 → road_1_3_0 → road_2_3_0 → road_3_3_3`
- Native `set_vehicle_route` accepted it.
- Native route readback exactly matched the requested route.
- Actual visited-road trajectory exactly matched the new route.
- The second fault's actual phase was independently read for 300 samples; all 300 samples were phase 1.
- The vehicle reached the destination at simulation time 1652.
- The trajectory did not traverse the blocked movement.

This demonstrates one real dynamic event, plan invalidation, lane-feasible rerouting, actual trajectory verification, and read-only observation. It does not demonstrate an LLM decision or agent collaboration.

## Matched wait-versus-reroute baseline

GitHub Actions run: `42494972478`  
Commit: `1e38863ee8056f0a2421f09e917d22691d34099d`  
Artifact: `dynamic-traffic-event-evidence`, ID `13623117388`

Both arms start from a fresh CityFlow engine with the same seed, same initial route, same first fault, same second fault, and 3000-second observation horizon. The only intervention is whether the vehicle is rerouted.

For the 300-second fault:
- Wait on original route: arrival at simulation time 1347.
- Reroute immediately: arrival at simulation time 1652.
- Rerouting is 305 simulated seconds slower.

This is a critical negative result: a successful reroute is not necessarily a better decision. When the fault is expected to clear soon, waiting may dominate the detour.

## Fault-duration sensitivity sweep

GitHub Actions run: `42495116598`  
Commit: `ed9b6aba891af4248173860b48fa635cd61836bf`  
Artifact: `dynamic-traffic-event-evidence`, ID `13622699565`

Same event location, initial route, traffic seed and 3000-second horizon; only the injected second-fault duration changes.

| Fault duration | Wait arrival | Reroute arrival | Reroute minus wait | Faster |
|---:|---:|---:|---:|---|
| 120 s | 1310 | 1652 | +342 s | Wait |
| 300 s | 1347 | 1652 | +305 s | Wait |
| 600 s | 1777 | 1652 | -125 s | Reroute |
| 900 s | 1973 | 1652 | -321 s | Reroute |

This gives a decision boundary between 300 and 600 simulated seconds in this single scenario. It is not a universal threshold: the boundary depends on route geometry, queue state, event location, vehicle, signal plan and network constraints. A proper study must vary these and include uncertainty in restoration-time estimates.

## Revised problem formulation

The next task should not be “always reroute when the current plan becomes invalid.” It should be:

**Given a route plan, a new controller fault, current traffic evidence, and an uncertain restoration-time estimate, choose between waiting, rerouting, or requesting further evidence; then execute and verify the choice under network constraints.**

This is more compelling because the agent must trade off:
- remaining fault duration,
- detour travel time,
- lane-feasible route availability,
- network queue impact,
- uncertainty and the value of waiting for new evidence.

The static nine-candidate task remains only a regression test. The new dynamic task is now a plausible candidate for the real agent evaluation.

## Next experiments

1. Expand to several event locations and multiple vehicle IDs; do not select scenarios based on favourable outcomes.
2. Use multiple fixed traffic seeds and publish every scenario, including failures.
3. Estimate a wait-versus-reroute decision boundary on a development set; evaluate on held-out locations/durations.
4. Build a stateful dynamic-event tool service with versioned event updates, lane-feasible candidate routes, wait/reroute execution, and independent trajectory/phase/queue verification.
5. Run a fair local Qwen3-8B single-agent baseline through native AIOS on the new task.
6. Only then run event-triggered professional roles using the evidence-bound collaboration ledger. A pair counts only when the requester consumes a reply and emits a revision.
7. Compare deterministic planner, strong single agent, serial heterogeneous team, parallel heterogeneous team and no-feedback team. Give each mode an independent equal deadline and repeat runs with balanced order.

## Still unproven

- Multi-agent collaboration is necessary or better than a strong single agent.
- Four distinct agent types and four necessary parallel subtasks are implemented.
- Three pairs of bidirectional interactions causally change work.
- At least 20% full-task concurrent speedup is achieved.
- Performance on the user's RTX 4090.
- Generalization beyond this one vehicle, route and road network.


## Matched baseline and duration sweep update

A later matched experiment extended the same deterministic scenario:
- Rerouted plan reached the destination at simulation time 1652.
- No-replan baseline, with identical initial route, same two faults, same seed and 3000-second horizon, reached at simulation time 1347 for the 300-second fault.
- The rerouted plan was therefore 305 simulated seconds slower in the 300-second case.

A controlled duration sweep then varied only the second fault duration, with fresh engines and the same seed for each wait/reroute arm:

| Second fault duration | Wait arrival | Reroute arrival | Reroute minus wait | Faster |
|---:|---:|---:|---:|---|
| 120 s | 1310 | 1652 | +342 s | Wait |
| 300 s | 1347 | 1652 | +305 s | Wait |
| 600 s | 1777 | 1652 | -125 s | Reroute |
| 900 s | 1973 | 1652 | -321 s | Reroute |

The decision boundary for this single route/vehicle/roadnet lies between 300 and 600 seconds. This is a development result, not a general threshold. It demonstrates that automatic rerouting is not always beneficial and that incident duration is decision-critical.

Source run: GitHub Actions `42495116598`, commit `ed9b6aba891af4248173860b48fa635cd61836bf`, artifact ID `13622699565`.

## Revised next task

The dynamic task should require the system to decide between:
- wait for controller restoration,
- reroute around the blocked movement,
- or request additional evidence before committing.

The decision must account for estimated restoration time and its uncertainty, lane-feasible route availability, actual queue impact and destination deadline. The restoration duration used by the simulator should remain hidden from the agent; the agent sees only the declared estimate/evidence. Evaluation should vary actual duration and estimate error.

This is a more defensible task than “always reroute after a plan becomes stale”. It creates a real decision problem where a successful action can still be suboptimal.
