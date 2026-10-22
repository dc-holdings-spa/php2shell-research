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

## 5. Cross-SAPI map and negative results

- One-shot CGI exposed the parsing differential but could not preserve state
  between requests.
- Persistent Windows CGI did not reproduce the expected stale-state consumer
  or large-cookie leak.
- Windows `mod_php` reproduced the memory cliff; 240 PageHeap-assisted attacks
  produced no crash for the tested request forms.
- Linux `mod_php` reproduced the parser differential and the early session
  consumer signature, but not controlled engine corruption.

These negative results narrow the useful search space and prevent clean OOMs
or unrelated crashes from being reported as exploitation.

## 6. Derived authorized-lab check

The midpoint of the measured cliff provides a one-request differential for the
tested versions. This repository intentionally does not publish the network
driver. The retained implementation must be used only in an isolated or
explicitly authorized environment, with worker health and capacity monitored.
