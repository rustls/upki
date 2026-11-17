# Frequently asked questions

This page collects common questions and answers about upki's current behavior.
See the [README](README.md) and [PACKAGING.md](PACKAGING.md) for detailed deployment
guidance.

## Architecture

### Does using upki require running a daemon?

No. `upki fetch` updates a cache on disk and then exits. A system timer, cron job,
or similar scheduler normally runs it periodically. TLS integrations read the
cache directly without the need for any kind of IPC to a daemon.

### Does certificate verification make network requests?

No. Revocation checks use only the local cache. Network access happens separately
when `upki fetch` contacts the configured mirror. A revocation check does not
disclose its destination to the upki mirror.

### Does upki replace normal certificate verification or the system trust store?

No. In its current state, path building, signature verification, validity,
hostname, and trust-anchor checks still happen in the TLS verifier that
integrates with upki. upki can reject a certificate that otherwise verifies, but
it crucially cannot make an otherwise invalid certificate trusted. In the future
we may consider extending the scope of upki to include this verification.

## Coverage and policy

### What certificates and revocation events does upki cover today?

The current revocation data covers publicly trusted, certificate transparency
logged end-entity certificates. It does not yet cover revoked intermediate or
root certificates.

### Would upki have protected against the eMudhra incident?

Not in its current form: responding to that incident required distrust of
intermediate and root certificates. [OneCRL support][onecrl], which would cover
emergency intermediate revocations, is being considered. The upki infrastructure
is a solid foundation to build capabilities that would have allowed quick
remediation of this incident without software updates.

[onecrl]: https://github.com/rustls/upki/issues/229

### Does upki support private PKI or client-certificate revocation?

Not through the currently supplied data and integrations. They target public
web PKI server certificates. Private PKI and client certificates need a separate
revocation policy and data source.

### What does “not covered” mean? Is it the same as “not revoked”?

No, they are not the same. `NotCoveredByRevocationData` is an inconclusive result.
It may occur because the certificate is newer than the cache data, or because
its issuer is not represented. In contrast, `NotRevoked` means the available
data covered the certificate and did not report it revoked.

### What happens when the cache is missing, stale, unreadable, or malformed?

Missing data and an uncovered certificate are policy decisions made by the TLS
integration. Unreadable or malformed data is reported as an error. Stale data may
miss recent certificates or revocations, so deployments should keep the cache
updated. See the
[`rustls-upki` policy](rustls-upki/README.md#error-handling-policy) and the
[OpenSSL callback documentation](upki-openssl/upki-openssl.h) for their behavior.

## Deployment and operations

### How is the cache updated, and how often should `upki fetch` run?

Run `upki fetch` from a system timer or similar scheduler. The 
[packaging guidance](PACKAGING.md#run-upki-fetch-regularly) recommends fetching
about every two hours and after network-up events.

### Who operates the revocation-data server, and can I use another mirror?

The default configuration uses the rustls project mirror, but the fetch URL is
configurable. Distributions, organizations, and users can operate their own
public or network-local mirrors. The [`upki-mirror`][upki-mirror] tooling can
be used to set up your own mirror.

[upki-mirror]: ./upki-mirror/README.md

### How is downloaded revocation data authenticated?

`upki fetch` authenticates its configured mirror using HTTPS and checks filter
contents against SHA-256 hashes in the downloaded manifest. The manifest does
not currently have a separately verified signature.

### How should upki be used in containers?

A container can mount the host's configuration and cache read-only, while the
host keeps the cache updated. Alternatively, the container must arrange its own
periodic fetches. upki does not require or provide a resident daemon.

### How much disk space and network traffic does upki use?

Populating an empty cache currently downloads around 10 MB. Subsequent fetches
use a conditional `If-Modified-Since` request, so if the manifest is unchanged,
the server can return `304 Not Modified`. In this case the client won't download
the unchanged manifest or any filters. Otherwise, the manifest is roughly 1.5
KB.

### What does a revocation check cost, and can a process cache the data in memory?

The disk-backed [`revocation-check` benchmark][revocation-benchmark] is currently
on the order of 10 ms per check. It includes constructing the lookup input from
the certificate chain and reading the index and relevant filters, so the exact
cost depends on the filesystem and cache state. Reading from disk also makes
updates visible without restarting the process. An in-memory option for
high-throughput users is under discussion in [pull request #279][loaded-store].

[revocation-benchmark]: https://app.codspeed.io/rustls/upki/benchmarks/revoke-test/benches/bench.rs::benches::revocation::revocation-check?runnerMode=Simulation
[loaded-store]: https://github.com/rustls/upki/pull/279

## Integrations and interoperability

### Which integrations are available, and is upki enabled automatically?

The project makes available:

* a `upki` command line tool (see [packaging status])
* a [rustls] verifier, [rustls-upki]
* an OpenSSL verifier, [upki-openssl]
* a native [Rust API]
* a [C API]

Note that installing the upki CLI alone does not change TLS behavior. An
application or distribution must enable an integration in verifiers using one of
the existing options, or via the Rust/C APIs.

[packaging status]: https://github.com/rustls/upki#packaging
[Rust API]: https://crates.io/crates/upki
[rustls]: https://rustls.dev
[rustls-upki]: https://crates.io/crates/rustls-upki
[upki-openssl]: https://github.com/rustls/upki/blob/main/upki-openssl/upki-openssl.h
[C API]: https://github.com/rustls/upki/blob/main/upki/upki.h

### Can software written in other languages consume the CRLite cache directly?

Yes. For CRLite revocation data the versioned [C2SP `upki-revocation`
specification][cache-spec] defines the cache layout and lookup procedure
independently of the Rust implementation.

[cache-spec]: https://c2sp.org/upki-revocation@v1.0.0

### Is the on-disk CRLite cache format stable and versioned?

The published v1.0.0 specification identifies its index and filter encodings,
and both carry versioned headers. Breaking changes are not expected at this
time. Future updates will follow semantic versioning and use updated headers.

## Roadmap

### What is planned beyond end-entity certificate revocation?

We're currently evaluating a number of extensions:

* intermediate preloading ([#302])
* intermediate and root distrust ([#229], [#294])
* certificate-transparency enforcement ([#303])
* Merkle Tree Certificate landmark distribution ([#304])

These are goals rather than a committed schedule. We encourage users with
specific needs to consider funding the project as a means of accelerating
this future work and providing input to the roadmap.

[#302]: https://github.com/rustls/upki/issues/302
[#294]: https://github.com/rustls/upki/issues/294
[#229]: https://github.com/rustls/upki/issues/229
[#303]: https://github.com/rustls/upki/issues/303
[#304]: https://github.com/rustls/upki/issues/304
