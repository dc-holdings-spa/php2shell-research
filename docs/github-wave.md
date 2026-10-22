# Same-day GitHub repository wave

This is a time-bounded snapshot collected on 2026-10-21, hours after the
coordinated disclosure.

## Observed scale

- 267 repository search results for `php2shell`.
- 232 results for `CVE-2026-109618`.
- 217 results for `CVE-2026-109619`.
- 39 repositories carrying the `php2shell` topic.

We observed three broad groups: substantive same-day research, one-commit
copies on fresh accounts, and keyword or star farming. We also found defensive
scanners and unrelated projects using the same topic.

## Deep-audit sample

Five repositories received file-level static review. We found:

- a copied repository whose README still instructed users to clone the
  original upstream;
- a repository unrelated to PHP2Shell using the keyword and a handle similar
  to the discoverer's;
- public proof-of-concept tooling mixed with star-farming language;
- a default URL apparently pointing at a real third-party path in one tool;
- no confirmed credential theft, telemetry, downloader, obfuscated payload,
  or exfiltration in the inspected files.

## Limits

Only five repositories received deep audits and roughly ten additional
READMEs were reviewed. Approximately 250 long-tail results were not inspected.
The statement “no malware confirmed” applies only to the inspected sample and
is not a safety certificate for the wider repository wave.

Repository counts and stars are a snapshot and will drift over time.

## Operational lesson

Same-day exploit searches mix primary research, defensive work, copies, and
attention farming. Review code statically, remove embedded targets, rebuild
from primary advisories when practical, and execute only inside disposable
environments without reusable credentials.
