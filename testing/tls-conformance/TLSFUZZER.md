# TLSfuzzer client CertificateVerify profile

`evidence-tls` now requires the external profile in `tlsfuzzer.py` in addition to
its existing client-certificate, listener-isolation and testssl checks. Its scope
is **TLS 1.3 mandatory client authentication / RSA-PSS CertificateVerify profile**,
not certification of the entire TLS standard or the entire TLSfuzzer project.

The upstream repository is pinned to
`5eebc4464e5197a7f7392fb9acda99cfc32441f7`. Both entry-point and application bytes
are SHA-256 checked. Runtime dependencies are fully version/hash locked in
`tlsfuzzer-requirements.lock`; a private virtual environment and source checkout
live in the evidence rig's disposable workspace.

The unmodified version-9 `test-tls13-certificate-verify.py` application generates
the tests and judges every handshake. For the rig's RSA-2048 client certificate,
the complete applicable roster is:

- Two sanity handshakes, first and last.
- Twelve signature-algorithm cases from the pinned `RSA_SIG_ALL` dependency
  roster: RSA PKCS#1 with MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 and RSA-PSS
  rsae/pss with SHA-256/SHA-384/SHA-512. Only the matching advertised TLS 1.3
  RSA-PSS rsae signatures should work; upstream defines each rejection alert.
- Three incorrect RSA-PSS salt lengths: 0, 31 and 33 bytes.
- Three signature/envelope, message-hash and MGF1-hash mismatch cases.
- Every single-bit malformed signature: 256 signature octets × eight bit flips.

That is **2,068 executions on each of three endpoints**: a real Python/OpenSSL
mandatory-client-auth control and the real Busbar data and admin TLS listeners.
Another upstream sanity execution using the rogue-CA client must fail specifically
with a fatal `unknown_ca` alert. This is a tool/fixture negative control, not a
passing Busbar result.

The sole configuration exclusion is `check sigalgs in cert request`: upstream
sends an empty client certificate and expects HTTP data, which requires optional
client authentication. The adapter never changes mandatory authentication to fit
that test. It explicitly names all applicable cases rather than using `-e`,
random sampling, expected failures or skips. Upstream's `-n 0` runs every selected
malformed-signature case. Missing cases, zero cases, unexpected skips, XFAIL,
XPASS, an incomplete summary or nonzero normal-leg exit all fail the profile.

Evidence is retained under `$CONFORMANCE_OUT/tlsfuzzer/`: complete expected
rosters, raw upstream logs, exact counts, partial counts on timeout/failure,
source revision/tree/change digest, distribution lock digest, subject binary
digest, upstream script/dependency pins and client-certificate digests. This
directory survives the evidence rig's temporary workspace cleanup.

Upstream retains its five-second socket timeout. Each full leg has a 900-second
process-group bound, the invalid-client control 120 seconds, and each bootstrap
step 120 seconds. There are no retries. CI must provide a suitable enclosing
`CONFORMANCE_TIMEOUT_SECONDS` and whole-job budget; the adapter does not alter CI.
Full protocol runs belong in CI. Local adapter-only checks open no TLS sockets:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -I testing/tls-conformance/test_tlsfuzzer_adapter.py
```

Published upstream test descriptions and implementation:

- https://github.com/tlsfuzzer/tlsfuzzer/blob/5eebc4464e5197a7f7392fb9acda99cfc32441f7/USAGE.md
- https://github.com/tlsfuzzer/tlsfuzzer/blob/5eebc4464e5197a7f7392fb9acda99cfc32441f7/tlsfuzzer/_apps/test_tls13_certificate_verify.py
- https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3
