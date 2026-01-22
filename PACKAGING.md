# Packaging `upki`
When distributed in a package, these are the main goals:

## Provide a system-wide configuration file
`upki` looks for this at `/etc/xdg/upki/config.toml` (before falling back to typical
per-user XDG locations.)  An example looks like:

```
cache-dir = "/var/cache/upki"

[revocation]
fetch-url = "https://example.com/"
```

`cache-dir` points `upki` at where to find its data files.  These should be
durable, but losing them only means more network traffic on the next `upki fetch` run.

`[revocation].fetch-url` is a HTTPS webserver where the data files should be made
available.  Notes on this:

- `upki` does not communicate with any server other than the configured one.
- You may wish to run your own mirror for your package or distribution.
- Your users may wish to run a site- or network-local mirror of their own.
- `upki` uses the installed CA certificates to establish the connection,
  so your package should have these as a dependency.

## Run `upki fetch` regularly
Currently the data is updated every twelve hours.  We would suggest running
`upki fetch` every two hours or so; the exact timing is a trade-off between
efficiency and latency.

Ideally it should also be run shortly after network-up events.

You may also consider running it during package installation.

Running `upki fetch` when there is nothing to do downloads a ~1.5KB JSON file.
This is usually very fast.

Running `upki fetch` when the cache is empty downloads up to ~10MB of data.

# Packaging checklist

- The executable `upki`, built in release mode.
- A system-wide configuration file at `/etc/xdg/upki/config.toml` which points
  at a `cache-dir` that may be read by any user needing to use `upki`.
- Arrangements to regularly run `upki fetch` as a low-privilege user who
  can write to the configured `cache-dir`.
