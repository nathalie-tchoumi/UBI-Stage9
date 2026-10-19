# Stage 9 — Incident Response Engineering Portfolio

A hands-on incident response engineering project focused on evidence processing,
timeline reconstruction, network artifact recovery, detection engineering, and
automated response validation.

## Technical areas

- Python-based parsing of endpoint, email, PowerShell, and network artifacts
- Structured event normalization and timeline reconstruction
- Automated tests for parsers and recovery logic
- Sigma detection rules for suspicious execution and persistence patterns
- Containment-action implementation and testing

## Repository structure

- `timeline_builder/` — parsers, event schema, timeline building, and recovery logic
- `detections/` — detection rules, containment logic, and tests
- `requirements.txt` — Python dependencies

## Evidence and reproducibility

This portfolio copy excludes original evidence archives and raw case artifacts.
The processing pipeline may require a separately authorized evidence dataset;
no incident evidence is included in this repository.

## Scope

This repository demonstrates incident response engineering practices in a
controlled training context. Detection logic should be validated against the
telemetry and logging configuration of the target environment before operational use.
