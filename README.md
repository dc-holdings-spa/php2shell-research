# PHP2Shell: independent validation and defensive research

Independent research by **Adversario Security Research**, operated by
**DC HOLDINGS SPA**. Lead researcher: **3ky**.

This repository documents our same-day validation of CVE-2026-109618 and
CVE-2026-109619, the observable differences between vulnerable and patched PHP
builds, and the public-repository wave that followed disclosure.

Published article:
[Español](https://adversario.cl/noticias/php2shell-laboratorio-adversario) ·
[English](https://adversario.cl/noticias/php2shell-laboratorio-adversario?lang=en)

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
- Controlled execution through the CVE-2026-109619 engine path on PHP 8.2.34
  FPM in an instrumented Linux lab: handler-pointer control and a chosen
  instruction pointer reproduced 3/3, followed by `system()` executing `id` as
  `www-data` in approximately 2/3 runs. The same recipe on 8.2.35 remained clean.
- A same-day snapshot of 267 GitHub search results and five deep static audits.
  We confirmed spam and attribution problems, but no malware in the inspected
  sample.

## Claim boundaries

We reproduced controlled execution through the CVE-2026-109619 engine path on
PHP 8.2.34 FPM under narrow laboratory conditions. This is not a portable or
self-contained remote exploit: ASLR was disabled, the harness planted the
producer session directly, the address-leak primitive was not reproduced, and
the result has not been ported beyond the tested build. The command-execution
exploit remains private.

We separately reproduced remote command execution through public,
application-dependent chains. Those chains also worked on fixed releases and
must not be presented as bypasses of the engine patch.

The Chain A reproduction required an LFI, a known session path,
`session.upload_progress.cleanup=Off`, and `session.use_only_cookies=0`. The
latter two are not PHP defaults. It succeeded on both vulnerable and patched
builds, so it must not be presented as proof of exploitation of the patched
engine defect.

See [Claims and scope](docs/claims-and-scope.md) before quoting this work.

## Research status

The first research phase is complete and supports publication: the patch
differential, FPM stale-state crash, controlled engine execution, cross-SAPI
map, forensic hypothesis, and same-day repository audit are documented with
explicit limits.

Follow-up work is focused on an address leak with ASLR enabled, portability,
the observed heap-alignment variance, and stronger defensive artifacts.

## Repository map

- [`docs/methodology.md`](docs/methodology.md): isolated lab and validation method.
- [`docs/findings.md`](docs/findings.md): original observations and limits.
- [`docs/github-wave.md`](docs/github-wave.md): public-repository audit.
- [`docs/detection.md`](docs/detection.md): defensive monitoring guidance.
- [`docs/sources.md`](docs/sources.md): primary sources and attribution.
- [`docs/article-outline-es.md`](docs/article-outline-es.md): Spanish article structure.
- [`drafts/articulo-es.md`](drafts/articulo-es.md): Spanish long-form source
  snapshot. The bilingual Markdown rendered by adversario.cl is the published
  edition.
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
