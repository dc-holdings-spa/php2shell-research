# Detection and hunting guidance

No single signal below establishes exploitation. Correlate application,
reverse-proxy, process, and session evidence.

## Higher-value correlations

- PHP worker crash or access violation immediately after an external
  multipart request.
- Repeated memory-limit errors during request parsing followed by worker churn.
- Multipart bodies containing unusually many part headers, repeated fields, or
  empty file controls.
- Unexpectedly large or malformed PHP session cookies.
- New zero-byte session files correlated with session-decoding memory errors.

## Public-tool fingerprints

Some public tools used the following literals:

- User-Agent `php2shell-109618`;
- multipart boundary `B7kQpoc618`;
- command marker `JACKALPOC`.

These are narrow hunting indicators for known tools. An attacker can change
them trivially, and their presence does not prove successful exploitation.

## False-positive considerations

During our Windows Apache work, a per-directory INI configuration produced a
repeatable access violation on both vulnerable and patched builds. Worker churn
or an access violation without request context is therefore insufficient.

Likewise, zero-byte session files can have ordinary operational causes. Use
them only as a correlation signal.

## Immediate response

1. Confirm the installed PHP runtime, not only the CMS version.
2. Apply a fixed PHP release from the supported distribution channel.
3. Restart all PHP workers after changing session mitigations.
4. Preserve proxy logs, PHP error logs, process events, and relevant session
   metadata before cleanup.
5. Treat mitigation settings as temporary controls, not replacements for the
   fixed runtime.
