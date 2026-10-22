# Claims and scope

## Confirmed in our laboratory

1. A deterministic multipart parsing differential across four vulnerable and
   four patched Windows PHP builds under an 8 MiB `memory_limit`.
2. A 140,000/260,000 part-header memory cliff between PHP 8.4.26 and 8.4.27 in
   the tested Windows Apache environment.
3. Repeatable worker death on PHP 8.3.35 and survival on PHP 8.3.36 for the
   tested streamed-body case.
4. Producer-side out-of-memory inside session decoding, followed by a
   zero-byte session file in the tested setup.
5. On PHP 8.2.34 FPM, a producer OOM during the unserialize walk followed by a
   session upload-progress consumer produced a deterministic SIGSEGV. Matching
   14 MiB and 16 MiB trials on PHP 8.2.35 completed without a segfault.
6. Remote HTTP command execution through public Chain A in a deliberately
   vulnerable Linux lab, on both PHP 8.4.26 and 8.4.27.
7. Application-dependent command execution through the public handler-mismatch
   chain on both vulnerable and patched Windows builds.
8. On PHP 8.2.34 FPM in an instrumented Linux lab, attacker-controlled
   multipart content supplied an object handler-table pointer. A chosen marker
   fault reproduced three out of three times, a chosen instruction-pointer
   value reproduced three out of three times, and `system()` executed `id` as
   `www-data` in approximately two out of three runs. The matching PHP 8.2.35
   recipe completed without execution or crash.

## Not demonstrated by us

- A portable engine-memory-corruption exploit across PHP builds or SAPIs.
- A self-contained remote engine exploit with ASLR enabled.
- The large PHPSESSID heap-leak primitive in our Windows CGI setup.
- Malware across the complete set of 267 GitHub search results.

The FPM result demonstrates controlled engine execution under laboratory
conditions. ASLR was disabled, the producer session was planted directly by
the harness, and the address leak needed for a real deployment was not
reproduced. Those limits must accompany any reference to engine-level RCE.

## Required wording for application-dependent RCE

Chain A required all of the following in the reproduced lab:

- a vulnerable local-file-inclusion sink;
- a known session storage path;
- `session.upload_progress.cleanup=Off`;
- `session.use_only_cookies=0`.

The two INI values are not PHP defaults. Because the chain also ran on the
patched build, it is evidence of the surrounding application/session surface,
not proof that the fixed engine vulnerability remained exploitable.

## Evidence labels

Every statement should be labeled as one of:

- **Primary source:** PHP advisory, GHSA, patch commit, or regression test.
- **Third-party research:** Calif, Wiz, Qi Deng, ikow, or another cited author.
- **Adversario observation:** produced by our lab and backed by retained logs.
- **Hypothesis:** plausible interpretation that still requires validation.
