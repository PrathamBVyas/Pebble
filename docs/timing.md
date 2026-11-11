# Timing

One 64 MiB file written through a read-write mount, then one fsync, then an
unmount and a read of the same file. The save syncs the new objects once
and renames HEAD. The number is from one run.

Machine: Linux 6.12.113+ x86_64, host name `cursor`
libfuse: 3.14.0

Write and fsync: 0.360 s
Read back: 0.057 s
