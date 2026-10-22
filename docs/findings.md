# Findings

## 1. Eight-build patch differential

A multipart body containing one file part and 220,000 part headers exhausted
the 8 MiB memory limit on all four vulnerable builds. All four patched builds
completed parsing and executed the script under the same configuration.

This was reproduced twice across all eight builds. It is useful as a version
differential in an authorized lab. It should not be described as a harmless
production scanner because it deliberately forces a high-memory parsing path.

## 2. The 140k/260k memory cliff

In Windows Apache `mod_php`, PHP 8.4.26 produced fatal memory exhaustion from
140,000 headers onward in three out of three runs at every tested size. PHP
8.4.27 parsed 260,000 headers in three out of three runs under the same 8 MiB
limit.

The result shows a large observable change in parsing behavior after the fix.
It does not, by itself, demonstrate exploitable corruption.

## 3. Repeatable PHP 8.3 worker death

With persistent FastCGI and a streamed body containing 200,000 variables, PHP
8.3.35 died during transmission in three out of three runs. PHP 8.3.36 remained
alive in all three corresponding runs. Other branches did not reproduce the
same death with that body, consistent with allocator and layout sensitivity.

## 4. Zero-byte session artifact

When the producer exhausted memory inside session deserialization, the tested
environment left the associated session file truncated to zero bytes. This is
a useful forensic hypothesis when correlated with PHP memory errors, session
activity, and request timestamps. A zero-byte session alone is not a reliable
indicator of exploitation.

## 5. PHP-FPM stale-state crash differential

The original 5 MiB/8 MiB calibration exhausted memory while allocating the
initial hash table, before the unserialize walk had populated useful state.
Under a 32 MiB limit, producer session graphs of 14 MiB, 16 MiB, and 18 MiB
instead failed during the walk with small allocation requests.

On PHP 8.2.34 FPM, the first upload-progress consumer after each producer
generated SIGSEGV. The 14–18 MiB cases reached the same instruction offset for
the observed runs, while their fault addresses varied with the graph size. A
repeated 14 MiB run reproduced both the instruction offset and fault address.

With the same producer and consumer design on PHP 8.2.35, the 14 MiB and 16 MiB
cases produced six clean application responses each and no segfaults. FPM logs
for the vulnerable case recorded the full order:

```text
Fatal error: Allowed memory size ... exhausted (tried to allocate 4096 bytes)
Warning: Unknown: Failed to decode session object
child exited on signal 11 (SIGSEGV)
```

This closed the initial vulnerable-versus-patched engine crash differential
consistent with CVE-2026-109619 and supplied the oracle used in the controlled
execution work below.

## 6. Controlled engine execution in the instrumented FPM lab

The debugger backtrace placed stale-state consumption in `var_tmp_var`, below
`rfc1867_post_handler` during request startup. Subsequent trials reclaimed a
stale object slot with multipart content and caused the engine to obtain the
resurrected object's handler-table pointer from attacker-controlled bytes.

The evidence ladder was:

- controlled handler-table marker fault: three out of three runs;
- chosen instruction-pointer value: three out of three runs;
- `system()` executing `id` as `www-data`: approximately two out of three runs;
- the same recipe on PHP 8.2.35: no command execution and no crash.

This demonstrates execution through the CVE-2026-109619 engine path on PHP
8.2.34 FPM under the tested conditions. ASLR was disabled, the harness planted
the producer session directly, no address leak was reproduced, and the result
has not been ported to other builds. The exploit and raw memory artifacts are
not part of this public repository.

## 7. Cross-SAPI map and negative results

- One-shot CGI exposed the parsing differential but could not preserve state
  between requests.
- Persistent Windows CGI did not reproduce the expected stale-state consumer
  or large-cookie leak.
- Windows `mod_php` reproduced the memory cliff; 240 PageHeap-assisted attacks
  produced no crash for the tested request forms.
- Linux `mod_php` reproduced the parser differential and the early session
  consumer signature without a crash in the tested forms.
- Linux FPM 8.2.34 reproduced the producer/consumer SIGSEGV; PHP 8.2.35 remained
  clean in the matched controls described above.

These negative results narrow the useful search space and prevent clean OOMs
or unrelated crashes from being reported as exploitation.

## 8. Derived authorized-lab check

The midpoint of the measured cliff provides a one-request differential for the
tested versions. This repository intentionally does not publish the network
driver. The retained implementation must be used only in an isolated or
explicitly authorized environment, with worker health and capacity monitored.
