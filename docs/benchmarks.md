# Benchmarks

One run of `python scripts/bench.py` on Ubuntu 24.04.5 LTS, Linux 6.12.113+ x86_64, Python 3.12.3, fusermount3 3.14.0. The script builds a temporary volume, deletes it, and prints this table. Run it again on the machine you are judging from; these numbers are that one run, not a promise about another machine.

Password checks use Argon2id at 19 MiB and 2 iterations. Each `put`, `commit`, and `read` unlocks again, so those lines include the stretch. The mount lines start after the folder is already mounted, and they time only the write plus fsync, then a later read.

| Measurement | Time | Detail |
| --- | ---: | --- |
| Wrong password | 0.023 s | clear refusal, Argon2id |
| Open and read a small file | 0.019 s | includes the password stretch |
| Save 1 MiB | 0.056 s | 17.8 MiB/s, put and commit |
| Read 1 MiB | 0.022 s | 45.8 MiB/s, includes the password stretch |
| Save 8 MiB | 0.113 s | 70.8 MiB/s, put and commit |
| Read 8 MiB | 0.043 s | 184.5 MiB/s, includes the password stretch |
| Tampered object | 0.037 s | one flipped byte, read refused |
| Restored older HEAD | 0.019 s | status exit 2, rewind |
| Mount write 64 MiB and fsync | 0.380 s | one save, objects synced once then HEAD renamed |
| Mount read 64 MiB | 0.026 s | after unmount and a fresh read-only mount |

The 64 MiB mount write is the same shape as the earlier single-file note in [timing.md](timing.md): one fsync publishes one save, the new objects are synced once, and `HEAD` is renamed after that. On this run that write took 0.380 s and the read back took 0.026 s.

The tamper line is the check that a changed byte does not come back as the file. The rewind line is the check that putting an older `HEAD` back is noticed. Both refused the bad state.
