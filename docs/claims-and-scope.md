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
5. Remote HTTP command execution through public Chain A in a deliberately
   vulnerable Linux lab, on both PHP 8.4.26 and 8.4.27.
6. Application-dependent command execution through the public handler-mismatch
   chain on both vulnerable and patched Windows builds.

## Not demonstrated by us

- Instruction-pointer control through the engine corruption.
- A complete heap-grooming chain against the tested builds.
- End-to-end engine-memory-corruption RCE for CVE-2026-109618 or
  CVE-2026-109619.
- The large PHPSESSID heap-leak primitive in our Windows CGI setup.
- Malware across the complete set of 267 GitHub search results.

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
