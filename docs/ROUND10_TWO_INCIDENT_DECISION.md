# Round 10 — Multi-vehicle, multi-incident joint response

Date: 2026-11-16

## Scope

This round continues the AIOS-based urban traffic dynamic-event platform. The goal is to test whether simultaneous faults at distinct intersections create a stronger network-coupling task than the earlier one-event case.

This is a deterministic native CityFlow experiment. It is not an LLM, AIOS, multi-agent or competition-speedup result. No real roads, signals or vehicles were controlled. No independent subagent execution interface was available in this session.

## Prior one-event eight-vehicle result: correction

A separate one-event eight-vehicle experiment (GitHub Actions run 43846116043) evaluated all 256 assignments. An audit found that its reported local-best mask was reversed because the script mixed least-significant-bit vehicle indexing with a most-significant-bit-first display string.

After independently recomputing each vehicle's singleton action from the 256 saved result files:
- vehicle-order actions: `[wait, reroute, reroute, wait, reroute, reroute, wait, wait]`
- correct displayed mask: `00110110`
- this exactly equals the exhaustive global optimum, total arrival 12,294.
- therefore the original claim that local choices were 741 seconds worse than all-wait is withdrawn.

See `docs/ROUND10_EIGHT_VEHICLE_AUDIT.md`. Original artifact and source summary remain immutable.

## Current two-event experiment design

- Public road network: CoLLMLight Hangzhou 4×4 fixed demand trace.
- Pinned CityFlow commit: `81ee0f47659ca66177a71f81676691c58ee89184`.
- Pinned CoLLMLight commit: `ce204a90a238e206fa5673b6922aab3a6a9fc597`.
- Demand and roadnet SHA256 are checked before execution.
- Existing background hold: `intersection_2_3`, phase 2, from t=700 to t=1500.
- Two additional simultaneous signal-controller faults at t=705, each held at phase 1 for 540 simulated seconds:
  - `intersection_1_3`
  - `intersection_3_3`
- Four lane-feasible vehicles are selected per affected intersection before outcomes are run, with distinct current roads globally.
- Each vehicle chooses wait or reroute. All 2^8 = 256 joint assignments are simulated from fresh identical engines.
- Every selected route is checked against current road, drivable lane and original route before action.
- Actual visited-road trajectory, destination, both fault phases and global queue are recorded.
- Feasibility cap: mean global queue no more than 5% above all-wait. This is an experimental contract, not a real traffic safety threshold.

## Execution status

The GitHub Actions workflow is `.github/workflows/round10-two-incidents.yml` on branch `round10-multi-incident-20261116`. The run ID and final artifact are recorded after completion. Do not infer success from a queued/in-progress state.

## Results

Pending native run completion. No result is claimed until all 256 records and the final manifest are available and independently audited.

## Required interpretation

Even if the local-best action combination is worse than the joint optimum, this is evidence of non-additive network effects, not proof that four LLM agents are necessary. A deterministic solver, a fully equipped single 8B agent, and an event-triggered heterogeneous team must still be compared fairly with identical tools, observations and budgets.

The next system-level experiment must demonstrate that peer feedback changes a concrete artifact or action and that the change improves held-out task outcomes. Full serial/parallel timing must include model inference, queueing, communication, tool execution, retries and verification.
