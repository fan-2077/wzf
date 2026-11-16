# Round 9 reproduction notes

The local evidence package is `AIOS_round9_joint_traffic_evidence_20261116.zip` (138 files, manifest verified). It contains:
- 24 individual vehicle wait/reroute rollouts (4 vehicles × 3 durations × 2 actions);
- 16 joint assignments (2^4);
- pre-outcome frozen vehicle selection;
- full per-vehicle trajectories, queue samples and fault phase observations for individual pairs;
- joint assignment outputs, independent JSON audit (177 checks), fixed source restoration and native build records.

The fixed Round 2 source archive is not duplicated in this repository branch. Reproduction requires the previously delivered `AIOS_round2_validation.zip`, whose SHA256 is recorded in `results/source_restoration.json`.

Commands (Python 3.13, Linux, g++, PyTorch's pybind11 headers or pybind11):
```bash
python src/restore_sources.py --archive /path/to/AIOS_round2_validation.zip
python src/build_native_o1.py
python src/discover_dynamic_candidates.py
python src/run_vehicle_sweep.py
python src/aggregate_vehicle_sweep.py
python src/run_joint_assignment_sweep.py
python src/verify_round9.py
```

The run is deterministic native simulation, not an LLM or AIOS run. The task is still solved by deterministic exhaustive enumeration over 16 joint actions; it is a coupling demonstration, not a multi-agent superiority result.
