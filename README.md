# PHP2Shell: independent validation and defensive research

Independent research by **Adversario Security Research**, operated by
**DC HOLDINGS SPA**. Lead researcher: **3ky**.

This repository documents our same-day validation of CVE-2026-109618 and
CVE-2026-109619, the observable differences between vulnerable and patched PHP
builds, and the public-repository wave that followed disclosure.

## What we found

- A deterministic vulnerable-versus-patched differential across eight PHP
  builds using the same multipart request and the same memory limit.
- A memory cliff on Windows Apache `mod_php`: PHP 8.4.26 exhausted an 8 MiB
  limit from 140,000 part headers, while PHP 8.4.27 parsed 260,000 in the tested
  environment.
- Repeatable worker death on PHP 8.3.35 under a streamed 200,000-variable body;
  PHP 8.3.36 survived all three matching runs.
- A zero-byte session artifact after the producer-side fatal condition, useful
  as a forensic hypothesis when correlated with memory errors and request logs.
- Different behavior across one-shot CGI, persistent FastCGI, Windows
  `mod_php`, and Linux `mod_php`, including negative results.
- A deterministic stale-state consumer crash on PHP 8.2.34 FPM after a
  producer-side mid-walk OOM; the matching PHP 8.2.35 control completed cleanly.
- A same-day snapshot of 267 GitHub search results and five deep static audits.
  We confirmed spam and attribution problems, but no malware in the inspected
  sample.

## Claim boundaries

We reproduced remote command execution through public, application-dependent
chains. We did **not** reproduce end-to-end command execution through the
engine memory-corruption path of CVE-2026-109618/109619.

We did reproduce an engine-level crash differential consistent with
CVE-2026-109619. A deterministic SIGSEGV is evidence of a memory-safety failure;
it is not evidence of instruction-pointer control or command execution.

The Chain A reproduction required an LFI, a known session path,
`session.upload_progress.cleanup=Off`, and `session.use_only_cookies=0`. The
latter two are not PHP defaults. It succeeded on both vulnerable and patched
builds, so it must not be presented as proof of exploitation of the patched
engine defect.

See [Claims and scope](docs/claims-and-scope.md) before quoting this work.

## Research status

The first research phase is complete and supports publication: the patch
differential, FPM stale-state crash, cross-SAPI map, forensic hypothesis, and
same-day repository audit are documented with explicit limits.

A follow-up will be published if subsequent debugger work identifies the exact
crashing structure or produces stronger defensive artifacts. Until then, the
FPM result remains an engine-level crash differential, not controlled
corruption or engine-level RCE.

## Repository map

- [`docs/methodology.md`](docs/methodology.md): isolated lab and validation method.
- [`docs/findings.md`](docs/findings.md): original observations and limits.
- [`docs/github-wave.md`](docs/github-wave.md): public-repository audit.
- [`docs/detection.md`](docs/detection.md): defensive monitoring guidance.
- [`docs/sources.md`](docs/sources.md): primary sources and attribution.
- [`docs/article-outline-es.md`](docs/article-outline-es.md): Spanish article structure.
- [`drafts/articulo-es.md`](drafts/articulo-es.md): private Spanish article draft.
- [`evidence/matrix-summary.csv`](evidence/matrix-summary.csv): sanitized build matrix.
- [`evidence/fpm-stale-state-summary.csv`](evidence/fpm-stale-state-summary.csv):
  sanitized PHP-FPM producer/consumer differential.
- [`detections/`](detections/): narrow indicators for known public tooling.

## Safe use

The repository does not publish a command-execution exploit. The differential
request deliberately drives PHP toward its memory limit and is therefore
described as an **authorized-lab check**, not a harmless production scanner.

Use only on systems you own or are explicitly authorized to test.

## Attribution

Discovery and primary technical credit belongs to Calif (Ryan Austin /
`lcfr_hax`), Wiz Research, and OpenAI, with the PHP maintainers who designed
and shipped the fix. Qi Deng and ikow documented additional public chains.
Our contribution is the independent matrix, cross-SAPI observations, forensic
artifact, FPM crash differential, patch differential, and same-day repository
audit described here.

Website: [adversario.cl](https://adversario.cl)
