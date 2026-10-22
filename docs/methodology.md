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

## Interpretation rules

- A fatal out-of-memory response is not command execution.
- A process crash is not controlled memory corruption.
- Command execution in an application-dependent chain is not engine-level RCE.
- A behavior seen in vulnerable and patched builds cannot establish that the
  fixed engine defect caused it.
- Negative results are scoped to the tested SAPI, build, allocator, and request
  form.

