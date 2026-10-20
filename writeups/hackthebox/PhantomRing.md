# PhantomRing — Hack The Box Sherlock

**Author:** Omar Mohammed Jaradat  
**Topic:** Linux malware analysis and reverse engineering  
**Method:** Static analysis

## Overview

This case study documents the methodology and findings of my PhantomRing Sherlock investigation. The challenge involves inspecting a suspicious Linux agent to understand its communication settings, enumeration capabilities, and host-inspection behavior.

## Investigation workflow

1. Preserve the challenge archive and analyze the extracted executable in an isolated environment.
2. Identify the executable format using `file` and inspect ELF metadata with `readelf`.
3. Calculate SHA-256 with `sha256sum` to document sample identity.
4. Extract potential indicators and function names with `strings` and `nm`.
5. Use Ghidra to inspect function cross-references and verify behavior rather than relying on strings alone.
6. Summarize observations as indicators and defensive detection opportunities.

## Findings

| Item | Finding |
|---|---|
| SHA-256 | `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5` |
| C2 address | `192.168.56.1` |
| Port | `4445` |
| Reconnection delay | 120 seconds |
| Unique supported command handlers | 11 |
| Kernel interface | `io_uring` |
| User session records | `/var/run/utmp` |
| SUID scan location | `/usr/bin` |
| BPF map descriptor | `anon_inode:bpf-map` |
| Tracing configuration path | `/sys/kernel/debug/tracing/tracing_on` |
| Process executable path | `/proc/self/exe` |
| Cleanup command | `sdestruct` |

## Technical observations

The agent uses a hardcoded connection destination and a fixed retry delay. The command parser supports eleven distinct handlers; `ss` and `netstat` refer to the same functionality and should not be double-counted. The appearance of `io_uring` is especially interesting for defensive monitoring because visibility depends on an EDR's telemetry architecture.

References to user session records, privileged program directories, BPF map descriptors, and tracing controls suggest a host-inspection capability. These individual references should be interpreted alongside the actual code paths before inferring successful privilege escalation or evasion.

## Detection opportunities

- Correlate suspicious ELF executions with unusual outbound connections.
- Review access to Linux session records and privileged executable directories.
- Monitor unexpected interaction with tracing and BPF-related interfaces.
- Preserve network and process telemetry to support incident reconstruction.

## Notes

This document summarizes results from a prior investigation. The underlying sample and screenshots are not embedded here; consult the challenge package to independently reproduce each finding. No malware binary is distributed.

*Independent educational writeup by Omar Mohammed Jaradat.*
