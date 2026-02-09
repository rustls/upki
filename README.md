<p align="center">
  <img width="460" src="https://raw.githubusercontent.com/rustls/upki/main/admin/upki.svg">
</p>

**upki** implements platform-independent browser-grade certificate infrastructure.

The first goal of this project is to provide reliable, privacy-preserving
and efficient certificate revocation building on foundational work by Mozilla.

Later goals include intermediate preloading, certificate transparency enforcement,
replicating common root distrust processes, and supporting deployment of
Merkle Tree Certificates.

## Revocation

This is for checking revocation status for certificates issued by publicly-trusted
authorities.  It uses [crlite-clubcard](https://eprint.iacr.org/2025/610).  This requires
a data set that updates several times per day.  `upki` therefore includes a synchronization
component, which fetches updated data.  You can run `upki fetch` to do this at any time,
but ideally it is run system-wide as [arranged by packagers](PACKAGING.md).

There are a number of interfaces available:

### Command-line interface
This is useful for monitoring, testing and alerting purposes.

```shell
$ curl -w '%{certs}' https://google.com | upki revocation check
(...)
NotRevoked
```

### C-FFI interface

TODO

### Rust crate

TODO

# Packaging

See [PACKAGING.md](PACKAGING.md).

# License

upki is distributed under the following two licenses:

- Apache License version 2.0.
- MIT license.

These are included as LICENSE-APACHE and LICENSE-MIT respectively. You
may use this software under the terms of any of these licenses, at your
option.
