# rustls-upki

[rustls](https://crates.io/crates/rustls) integration for
[upki](https://github.com/rustls/upki), providing browser-grade certificate
revocation checking for TLS clients.

This crate exposes a [`ServerCertVerifier`] that verifies a server certificate
in the usual way (using [`webpki`](https://crates.io/crates/rustls-webpki)
against a set of trusted roots) and then checks its revocation status using
upki's [crlite-clubcard](https://eprint.iacr.org/2025/610) data set.

Revocation checking requires a local copy of upki's revocation data, which
updates several times per day. See the [upki README] and [PACKAGING.md] for how
to fetch and install this data (typically `upki fetch`, or a system-wide setup
arranged by your packager).

[upki README]: https://github.com/rustls/upki/blob/main/README.md
[PACKAGING.md]: https://github.com/rustls/upki/blob/main/PACKAGING.md
[`ServerCertVerifier`]: https://docs.rs/rustls/latest/rustls/client/danger/trait.ServerCertVerifier.html

## Error-handling policy

`ServerVerifier::new` takes a [`Policy`] that controls how to behave in cases
where revocation status cannot be determined conclusively:

- When the local upki data is missing
- When a certificate is not covered by the revocation data
- When a certificate carries no SCTs, and so was not logged in Certificate
  Transparency, meaning it likely is not publicly trusted

Each case maps to an [`Outcome`]:

- Allow the connection
- Treat the certificate as revoked
- Return a specific error

`Policy::default()` errors when the data is missing, and allows the other two
cases.

## License

This crate is distributed under the terms of both the Apache License (Version
2.0) and the MIT license, at your option. See [LICENSE-APACHE] and [LICENSE-MIT]
in the repository root for details.

[LICENSE-APACHE]: https://github.com/rustls/upki/blob/main/LICENSE-APACHE
[LICENSE-MIT]: https://github.com/rustls/upki/blob/main/LICENSE-MIT
[`Policy`]: https://docs.rs/rustls-upki/latest/rustls_upki/struct.Policy.html
[`Outcome`]: https://docs.rs/rustls-upki/latest/rustls_upki/enum.Outcome.html
