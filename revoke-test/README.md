# revoke-test

Real-world certificate revocation integration tests and benchmarks for `upki`
and `rustls-upki`.

## Explainer

Browser-trusted CAs that participate in the [CCADB](https://www.ccadb.org/)
are required to maintain publicly accessible test websites whose TLS certificates
have been intentionally revoked. This crate uses those test websites to verify
that `upki`'s revocation checking correctly identifies revoked certificates in
practice.

Unfortunately, a snag is that such sites are occasionally unreliable. On top of that,
upki inherits an unpredictable latency to recognizing revocations. That means these tests are
fuzzy: we actually just require that a majority of sites are detected as revoked.

## Why do these tests rot?

`test-sites.json` is a JSON snapshot that records, for each CA in the CCADB, the URL
of its revoked test website together with details of the certificate chain it
presents.

Certificate chains presented by the test websites have varying lifetimes, but these
tests currently don't accept expired certificates.  That means the snapshot needs
to be regularly refreshed.

Refresh the snapshot with:

```
cargo run -p revoke-test --bin fetch
```

Then commit the updated `test-sites.json`.
