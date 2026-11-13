# Timing

The fuller table, including password refusal, tamper, and rewind, is in [benchmarks.md](benchmarks.md). This note is the single 64 MiB mount from that same run.

Machine: Linux 6.12.113+ x86_64, Ubuntu 24.04.5 LTS
libfuse: 3.14.0

Write and fsync: 0.380 s
Read back: 0.026 s

The save syncs the new objects once and then renames HEAD.
