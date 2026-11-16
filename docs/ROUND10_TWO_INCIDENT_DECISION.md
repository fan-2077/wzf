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


## Completed result — 8 vehicles, two simultaneous target incidents

GitHub Actions run: `43851493851`  
Artifact: `round10-two-incident-evidence`, ID `14219440036`  
Artifact SHA256: `acdc767b5d00a2abdcc082393fff7268096ea4fa2a076824f243fd847b929e38`

The run evaluated all 256 assignments in 311.468 seconds. All 256:
- completed;
- verified every selected vehicle's actual route and destination;
- independently observed both target fault phases for all 540 samples;
- satisfied the example queue cap of +5% versus all-wait.

Results:
- all-wait: mask `00000000`, sum arrival 12,723 simulated seconds, mean queue 90.7663;
- singleton-local choices: vehicle-order actions `[wait, wait, reroute, wait, wait, wait, reroute, wait]`, display mask `01000100`, sum arrival 12,138;
- joint optimum: display mask `01000010`, reroute `flow_1449_0` and `flow_1464_0`, sum arrival 12,111, mean queue 90.953.

**The singleton-local combination is not worse than all-wait.** The joint optimum improves it by only 27 simulated seconds. This is a small, measurable coordination effect in this one scenario, not a large advantage and not proof of multi-agent necessity.

The two mask labels use big-endian display strings, while vehicle index 0 is the least-significant/rightmost bit. The local-choice mask was independently recomputed using this mapping. The previous one-event 8-vehicle mask-order error is documented separately in `ROUND10_EIGHT_VEHICLE_AUDIT.md`.

The archive manifest contains 521 entries; independent SHA256 verification found zero missing or mismatched files. Full raw evidence remains in the artifact. The machine-readable audited summary is `results/round10_two_incident_summary.json`.

## Decision after this experiment

The two-event setup is a better task candidate than the single-event setup because it involves two different fault intersections and eight vehicles sharing the same network. However, the 27-second gap is too small to claim a compelling collaboration advantage. The current deterministic exhaustive solver still solves all 256 combinations.

Next, increase the task to 10 vehicles (five per affected intersection) while keeping the two-event structure and fixed observation protocol. Recompute the local-best assignment with explicit bit-index mapping and compare it with the exhaustive joint optimum. If the gap remains small or unstable, do not claim strong multi-agent necessity; investigate richer shared constraints or a different application.
