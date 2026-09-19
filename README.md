# L-PoPI — Legacy Simulation Artifacts

## Purpose

This repository preserves the software and simulation artifacts associated
with the original L-PoPI manuscript submission for experimental provenance
and transparency.

These artifacts correspond to the earlier simulation/prototype evaluation
and are **not the primary experimental evidence of the revised manuscript**.

The revised manuscript is supported by a separate implementation and
reproducibility repository containing physical ESP32 SRAM-PUF experiments,
BCH-C fuzzy-extractor validation, FE-to-ZK binding, Groth16/EVM measurements,
and revised behavioral-model experiments.

## Important Status of the Results

Several numerical claims reported during the original submission have been
superseded by the revised physical and controlled evaluation.

Consequently, numerical outputs reproduced from this repository should be
interpreted as **historical simulation results**, not as the final measured
results of the revised L-PoPI manuscript.

In particular, this repository must not be used as evidence for claims of:

- physical SRAM-PUF robustness on a device population;
- physical 100% recovery at 25% BER;
- ESP32-side Groth16 proving latency;
- final revised EVM gas consumption;
- final revised Cog-GAT performance;
- final revised DPI reduction;
- a fully integrated physical end-to-end deployment.

## Repository Contents

The preserved source artifacts include:

- `main_lpopi.py` — original L-PoPI simulation/prototype workflow;
- `main_lpopi-humainlog.py` — historical workflow/logging variant;
- `etape1_puf.py` — original PUF-related simulation code;
- `circuit.circom` — original Circom circuit;
- `verifier.sol` and `verifier2.sol` — historical Solidity verifier artifacts;
- `blockchain_notifier.py` — blockchain-related prototype code;
- `relayer.py` — historical relayer component;
- `ids_operator.py` — IDS-related component;
- `visual.py` and `robustness_curve.png` — historical analysis/visualization artifacts;
- `input.json`, `proof.json`, `public.json`, and `verification_key.json` —
  preserved Groth16 experiment artifacts;
- `old version/` — earlier preserved source variants.

Generated dependency directories, virtual environments, trusted-setup files,
compiled circuit artifacts, and other large generated files are intentionally
excluded from version control.

## Revised Implementation

The revised experimental implementation is maintained separately at:

https://github.com/bouchrarguig-byte/L-PoPI-Revised-Implementation

The revised repository should be used for the experimental claims reported
in the revised manuscript.

## Reproducibility Scope

This legacy repository is retained to document the provenance of the
original submission and to make the transition from simulation-based claims
to the revised experimental evaluation transparent.

It is not intended to overwrite, reinterpret, or retroactively modify the
original simulation code.

## Note on Generated Artifacts

Large or reproducible generated artifacts such as `node_modules`, Python
virtual environments, Powers-of-Tau files, proving keys, witness files, and
compiled Circom artifacts are excluded to keep this provenance repository
small and auditable.

The small JSON proof/public/verification artifacts preserved here are
included as historical experimental records.

## Citation

Please cite the associated L-PoPI manuscript when using these artifacts.

Final bibliographic information will be added after publication.
