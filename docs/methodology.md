# Methodology

## Test design

We compared four vulnerable and four patched official Windows x64 PHP builds:

| Branch | Vulnerable | Patched |
|---|---:|---:|
| 8.2 | 8.2.34 | 8.2.35 |
| 8.3 | 8.3.35 | 8.3.36 |
| 8.4 | 8.4.26 | 8.4.27 |
| 8.5 | 8.5.11 | 8.5.12 |

The principal comparison used `memory_limit=8M` and `post_max_size=64M`.
Requests were derived from the public advisories, the PHP patch regression
tests, and published technical descriptions. The initial harness was written
independently and used standard-library FastCGI framing.

Tests covered:

- one-shot CGI;
- persistent FastCGI;
- Windows Apache `mod_php`;
- Linux Apache `mod_php` for targeted reproduction.
- Linux PHP-FPM 8.2.34/8.2.35 with a static one-worker pool for the stale-state
  producer/consumer comparison.

The environment was isolated, snapshotted before testing, and bound to local
interfaces. Raw evidence and infrastructure identifiers remain private.

## Positive controls

We required an application marker in the response body to prove that PHP had
parsed the request and executed the target script. HTTP status, FastCGI
application status, and process exit codes were insufficient by themselves.

This requirement invalidated two early runs after we found three harness bugs:

1. an invalid empty record after `BEGIN_REQUEST`;
2. premature FastCGI stream terminators after each input chunk;
3. PowerShell here-string expansion that corrupted PHP fixtures.

Only runs collected after those defects were corrected entered the matrix.

## FPM stale-state comparison

The FPM comparison used `memory_limit=32M` and a single worker so the producer
and consumer were handled by the same process. Serialized session graphs were
calibrated until the producer OOM occurred during the unserialize walk rather
than while reading the session buffer or allocating the initial hash table.

On PHP 8.2.34, 14 MiB, 16 MiB, and 18 MiB producer files reached the mid-walk
condition and the first consumer produced SIGSEGV. The 14 MiB and 16 MiB cases
were repeated against PHP 8.2.35; six consumer requests completed for each case
without a segfault.

The Linux kernel and FPM logs establish the fatal-OOM → session-decode warning
→ SIGSEGV sequence. A later debugger phase located stale-state consumption in
`var_tmp_var` below `rfc1867_post_handler`, then used repeated marker controls
before replacing the chosen target with `system()` in the lab's libc.

The controlled-execution phase used one PHP 8.2.34 FPM worker with ASLR
disabled to keep addresses stable. The harness directly planted the producer
session, isolating the engine primitive from session-delivery questions. The
same recipe was run against PHP 8.2.35 as the patched control. These choices
make the result suitable for engine analysis, but they do not establish a
portable or self-contained remote exploit.

## Interpretation rules

- A fatal out-of-memory response is not command execution.
- A process crash is not controlled memory corruption.
- Command execution in an application-dependent chain is not engine-level RCE.
- A behavior seen in vulnerable and patched builds cannot establish that the
  fixed engine defect caused it.
- Negative results are scoped to the tested SAPI, build, allocator, and request
  form.
