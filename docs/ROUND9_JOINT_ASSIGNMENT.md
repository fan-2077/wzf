# Round 9 — Joint multi-vehicle route assignment under a dynamic signal fault

Date: 2026-11-16

## Decision

Keep the CityFlow traffic-event platform as the current experimental vehicle. Move the task definition from a single vehicle's wait-versus-reroute choice to a **joint assignment of wait/reroute actions for several vehicles sharing the same network and incident**.

This is a deterministic simulator experiment, not an LLM or multi-agent result. No independent subagents were available in this session. No real traffic infrastructure was controlled.

## Frozen scenario

- Simulator: pinned CityFlow commit `81ee0f47659ca66177a71f81676691c58ee89184`.
- Public demand: CoLLMLight Hangzhou 4x4, fixed demand file and SHA256 checked in the previous evidence package.
- Seed: 7. The demand file contains fixed arrival records; changing the seed does not create independent demand samples. Do not call seed changes generalization.
- Initial fault: existing controller hold at intersection_2_3 from t=700.
- Four vehicles selected before observing any action outcome, by a frozen rule: first four sorted vehicle IDs on distinct current roads with a lane-feasible alternative and a future movement controlled by intersection_1_3.
- At t=705, intersection_1_3 is held at phase 1 for 540 simulated seconds. The planned movement requires phase 2.
- Each vehicle independently has two allowed actions: wait on its current route or reroute using a lane-feasible alternative. All 2^4=16 assignments were evaluated in fresh identical simulations.

## Four selected vehicles

| Vehicle | Current road | Blocked movement |
|---|---|---|
| flow_1259_0 | road_0_2_0 | road_1_2_1 → road_1_3_1 |
| flow_1449_0 | road_2_2_2 | road_1_2_1 → road_1_3_1 |
| flow_1460_0 | road_3_2_2 | road_1_2_1 → road_1_3_1 |
| flow_1674_0 | road_1_1_1 | road_1_2_1 → road_1_3_1 |

Each selected vehicle had an alternative route checked against its current lane's first outgoing movement. Native route readback and actual visited-road trajectory were checked after execution.

## Main finding: independent best actions can be globally worse

At 540 seconds, separate vehicle-pair experiments recommend:
- flow_1259_0: wait (1536 vs 1819)
- flow_1449_0: reroute (1799 vs 1831)
- flow_1460_0: reroute (1707 vs 1802)
- flow_1674_0: wait (1464 vs 1819)

Applying those four independent local choices together gives assignment `0110`, with total arrival time 6769 simulated seconds. This is **136 seconds worse than all-wait** (6633).

The reason is an interaction: flow_1460_0's reroute is 1707 when selected alone, but 2082 when flow_1449_0 is rerouted at the same time. The detours interact through shared network traffic.

Exhaustive joint evaluation of all 16 assignments found `0100`—reroute only flow_1449_0—as the best feasible assignment:
- total arrival time: 6519
- all-wait total: 6633
- improvement over all-wait: 114 simulated seconds
- mean network queue: 87.3283 vs 88.07 for all-wait
- all 4 vehicles reached their destinations and followed their assigned routes
- the 540-second fault was independently observed at phase 1 for all 540 samples

All 16 assignments satisfied the example queue cap of at most +5% relative to all-wait. This cap is an experimental contract, not a real traffic safety standard.

## Why this changes the task design

The problem is no longer four independent rerouting decisions. It is a coupled assignment problem:
- each vehicle has local route feasibility and individual delay;
- detours share roads and create network externalities;
- a route that is individually beneficial may become harmful when another vehicle takes a competing detour;
- signal phase compatibility and incident duration constrain the joint plan.

This creates a legitimate reason to investigate cross-role feedback. Candidate roles:
1. incident evidence and restoration-time analysis;
2. lane-level route feasibility and per-vehicle alternatives;
3. network-wide congestion/externality analysis;
4. signal phase and coordinated release-window analysis.

These are candidate roles, not yet implemented agents. The experiment does not establish that four LLM agents are necessary: a deterministic exhaustive solver solved this 16-option case.

## Strong baselines required next

1. Deterministic exhaustive search over all joint assignments.
2. A fully equipped single Qwen3-8B agent with the same evidence, tools, candidate budget and ability to parallelize tools.
3. Four-role team with event-triggered peer feedback.
4. The same team without peer feedback.
5. The same team serial versus parallel, with independent equal deadlines and repeated runs.

The single-agent baseline must be allowed to run the same exhaustive solver. No information or tools may be withheld to manufacture a multi-agent advantage.

## Important corrections and limitations

- Round 8 seed variation was abandoned as an independence claim: this traffic input is a fixed demand trace. A direct seed-11 smoke run produced the same selected-vehicle arrival and queue metrics as seed 7.
- During the first vehicle-sweep implementation, the public observation field accidentally referenced the fixed demo vehicle rather than the selected vehicle. The original fields are retained; corrected selected-vehicle observations were reconstructed from the frozen pre-outcome candidate records, and the source was patched and smoke-tested. The corrected aggregate compares each wait/reroute pair using the selected vehicle's state hash.
- One initial optimized build attempt timed out; the O1 native build completed. An O0 build also completed but was too slow for the planned sweep.
- Only one event location, one fixed demand file, one seed and four vehicles were tested. This is not cross-network generalization.
- No new LLM calls, no AIOS runtime calls, no independent subagent runs, no 20% speedup, and no user RTX4090 measurement occurred in this round.

## Evidence

The accompanying local delivery package contains:
- 24 native vehicle-pair rollouts (4 vehicles × 3 fault durations × 2 actions);
- 16 complete joint assignments (2^4);
- frozen pre-outcome vehicle selection;
- full trajectories, queue samples and phase samples;
- independent aggregation and route/fault verification;
- exact source/build scripts and the retained seed/build caveats.
