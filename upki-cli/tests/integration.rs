// these tests won't run on windows due to insurmountable disagreements over path formatting,
// but should work ok on macOS and WSL
#![cfg(not(target_os = "windows"))]

mod data;

use core::error::Error;
use core::time::Duration;
use std::fs::{OpenOptions, create_dir};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::SystemTime;
use std::{fs, thread};

use insta::assert_snapshot;
use insta::internals::SettingsBindDropGuard;
use insta_cmd::assert_cmd_snapshot;
use jiff::fmt::rfc2822::DateTimeParser;
use tempfile::TempDir;

use crate::data::{EVOLUTION, HttpRoot, TYPICAL};

#[test]
fn version() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(upki().arg("--version"), @r###"
    success: true
    exit_code: 0
    ----- stdout -----
    upki 1.0.3

    ----- stderr -----
    "###);
}

#[test]
fn config_unknown_fields() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/config_unknown_fields/config.toml")
            .arg("show-config"),
        @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Error: failed to parse config file at tests/data/config_unknown_fields/config.toml

    Caused by:
        TOML parse error at line 1, column 1
          |
        1 | cache_dir = "tests/data/config_unknown_fields/"
          | ^^^^^^^^^
        unknown field `cache_dir`, expected one of `cache-dir`, `revocation`, `intermediates`


    Location:
        upki-cli/src/bin/upki.rs:[LINE]:[COLUMN]
    "#);
}

#[test]
fn show_config_path_fixpoint() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("/home/example/not-exist/yo.txt")
            .arg("show-config-path"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----
    /home/example/not-exist/yo.txt

    ----- stderr -----
    ");
}

#[test]
fn show_config_fixpoint() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_non_existent_dir/config.toml")
            .arg("show-config"),
        @r#"
    success: true
    exit_code: 0
    ----- stdout -----
    cache-dir = "not-exist/"

    [revocation]
    fetch-url = ""

    ----- stderr -----
    "#);
}

#[test]
fn verify_of_non_existent_dir() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_non_existent_dir/config.toml")
            .arg("verify"),
        @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Error: cannot read file "not-exist/revocation/manifest.json"

    Caused by:
        No such file or directory (os error 2)

    Location:
        upki-cli/src/bin/upki.rs:[LINE]:[COLUMN]
    "#);
}

#[test]
fn verify_of_empty_manifest() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_of_empty_manifest/config.toml")
            .arg("verify"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
}

#[test]
fn verify_of_empty_intermediates_manifest() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg("tests/data/verify_of_empty_intermediates_manifest/config.toml")
            .arg("verify"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
}

#[test]
fn fetch_of_empty_manifest() {
    let _filters = apply_common_filters();
    let (server, _filters) =
        http_server(PathBuf::from("tests/data/verify_of_empty_manifest/"), false);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @"GET /revocation/manifest.json  ->  200 OK (79 bytes)"
    );
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec!["index.bin", "manifest.json"],
    );
}

#[cfg(target_family = "unix")]
#[test]
fn fetched_cache_paths_are_world_readable() {
    let (server, _filters) =
        http_server(PathBuf::from("tests/data/verify_of_empty_manifest/"), false);
    let temp = TempDir::new().unwrap();
    let cache_root = temp.path().join("cache");
    create_dir(&cache_root).unwrap();
    fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o700)).unwrap();
    let config_file = temp.path().join("config.toml");
    fs::write(
        &config_file,
        format!(
            "cache-dir=\"{}\"\n\
             [revocation]\n\
             fetch-url=\"{}revocation/\"\n",
            cache_root.display(),
            server.url(),
        ),
    )
    .unwrap();

    let output = upki()
        .arg("--config-file")
        .arg(config_file)
        .arg("fetch")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fetch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let revocation = cache_root.join("revocation");
    assert_eq!(
        fs::metadata(&cache_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700,
        "fetch changed the configured cache root's mode"
    );
    assert_eq!(
        fs::metadata(&revocation)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755,
        "unexpected mode for {revocation:?}"
    );
    for path in [
        revocation.join("index.bin"),
        revocation.join("manifest.json"),
    ] {
        assert_eq!(
            fs::metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644,
            "unexpected mode for {path:?}"
        );
    }
}

#[test]
fn fetch_fails_when_index_cannot_be_built() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(PathBuf::from("tests/data/invalid_filter/"), false);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Error: cannot build index at "[TEMPDIR]/revocation/index.bin"

    Caused by:
       0: cannot decode file "[TEMPDIR]/revocation/bad.filter"
       1: failed to deserialize clubcard
       2: non-zero reserved0 byte after version

    Location:
        upki-cli/src/bin/upki.rs:[LINE]:[COLUMN]
    "#);
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (239 bytes)
    GET /revocation/bad.filter  ->  200 OK (13 bytes)
    "
    );
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec!["bad.filter"]
    );
}

#[test]
fn hash_mismatch_does_not_replace_existing_filter() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(PathBuf::from("tests/data/hash_mismatch/"), false);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);
    let filter = temp
        .path()
        .join("revocation/replace.filter");
    fs::write(&filter, b"existing contents").unwrap();

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Error: hash mismatch for file "[TEMPDIR]/revocation/replace.filter"

    Location:
        upki-cli/src/bin/upki.rs:[LINE]:[COLUMN]
    "#);
    assert_eq!(fs::read(filter).unwrap(), b"existing contents");
}

#[test]
fn full_fetch() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(&*TYPICAL, false);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (532 bytes)
    GET /revocation/filter1.filter  ->  200 OK (113 bytes)
    GET /revocation/filter2.delta  ->  200 OK (113 bytes)
    GET /revocation/filter3.delta  ->  200 OK (113 bytes)
    ");
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "index.bin",
            "manifest.json"
        ]
    );
}

#[test]
fn full_fetch_and_incremental_update() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(&*TYPICAL, false);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (532 bytes)
    GET /revocation/filter1.filter  ->  200 OK (113 bytes)
    GET /revocation/filter2.delta  ->  200 OK (113 bytes)
    GET /revocation/filter3.delta  ->  200 OK (113 bytes)
    ");
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "index.bin",
            "manifest.json"
        ],
    );

    // now server is updated to "evolution" which requires a partial update
    // compared to "typical"
    let (server, _filters) = http_server(&*EVOLUTION, false);
    write_config(&temp, server.url());
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (547 bytes)
    GET /revocation/filter4.delta  ->  200 OK (113 bytes)
    ");
    // filter2 could be deleted, filter4 is new
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "filter4.delta",
            "index.bin",
            "manifest.json"
        ]
    );

    // a fetch of the same manifest clears away "filter2.delta" as it is now unused
    let (server, _filters) = http_server(&*EVOLUTION, false);
    write_config(&temp, server.url());
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @"GET /revocation/manifest.json  ->  200 OK (547 bytes)");

    // filter2 is now deleted
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter3.delta",
            "filter4.delta",
            "index.bin",
            "manifest.json"
        ]
    );
}

#[test]
fn typical_incremental_fetch() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(&*TYPICAL, false);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    TYPICAL.seed_partial_cache(temp.path());

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");

    // only fetched the neccessary files
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (532 bytes)
    GET /revocation/filter2.delta  ->  200 OK (113 bytes)
    ");

    assert_eq!(list_dir(temp.path()), vec!["config.toml", "revocation",],);

    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "index.bin",
            "manifest.json"
        ]
    );
}

#[test]
fn fetch_not_modified() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(&*TYPICAL, true);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (532 bytes)
    GET /revocation/filter1.filter  ->  200 OK (113 bytes)
    GET /revocation/filter2.delta  ->  200 OK (113 bytes)
    GET /revocation/filter3.delta  ->  200 OK (113 bytes)
    ");

    // the local manifest was just written, so it is newer than the one on the server:
    // the second fetch is answered with 304 and stops there
    let (server, _filters) = http_server(&*TYPICAL, true);
    write_config(&temp, server.url());
    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @"GET /revocation/manifest.json  ->  304 Not Modified (0 bytes)"
    );

    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "index.bin",
            "manifest.json"
        ]
    );
}

#[test]
fn fetch_with_stale_local_manifest() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(&*TYPICAL, true);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);

    let manifest = temp
        .path()
        .join("revocation/manifest.json");
    TYPICAL.seed_partial_cache(temp.path());

    // pretend the local manifest is ancient, so the server's copy is newer
    OpenOptions::new()
        .write(true)
        .open(&manifest)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(86_400))
        .unwrap();

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(&config_file)
            .arg("fetch"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");

    // the conditional request is answered in full, and the missing filter is fetched
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /revocation/manifest.json  ->  200 OK (532 bytes)
    GET /revocation/filter2.delta  ->  200 OK (113 bytes)
    ");
    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "index.bin",
            "manifest.json"
        ]
    );
}

#[test]
fn typical_incremental_fetch_dry_run() {
    let _filters = apply_common_filters();
    let (server, _filters) = http_server(&*TYPICAL, false);
    let (temp, config_file, _filters) = temp_dir_and_config(server.url(), write_config);
    TYPICAL.seed_partial_cache(temp.path());

    assert_cmd_snapshot!(
        upki()
            .arg("--config-file")
            .arg(config_file)
            .arg("fetch")
            .arg("--dry-run"),
        @r#"
    success: true
    exit_code: 0
    ----- stdout -----
    3 steps required (113 bytes to download)
    - download 113 bytes from http://127.0.0.1:[PORT]/revocation/filter2.delta to "[TEMPDIR]/revocation/filter2.delta"
    - build index.bin into "[TEMPDIR]/revocation"
    - save new manifest into "[TEMPDIR]/revocation"

    ----- stderr -----
    "#);

    // fetched just the manifest
    assert_eq!(list_dir(temp.path()), vec!["config.toml", "revocation",],);

    assert_eq!(
        list_dir(&temp.path().join("revocation")),
        vec!["filter1.filter", "filter3.delta", "manifest.json"]
    );
}

fn upki() -> Command {
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--quiet")
        .arg("--package")
        .arg("upki-cli")
        .arg("--");
    cmd
}

fn http_server(root: impl HttpRoot, conditional: bool) -> (TestHttpServer, SettingsBindDropGuard) {
    let server = TestHttpServer::new(("127.0.0.1", 0), root, conditional).unwrap();

    // add a filter eliding the (OS-assigned) port in logs
    let mut current_filters = insta::Settings::clone_current();
    current_filters.add_filter(&format!(":{}/", server.port), ":[PORT]/");

    (server, current_filters.bind_to_scope())
}

fn list_dir(path: &Path) -> Vec<String> {
    let mut list = fs::read_dir(path)
        .unwrap()
        .map(|p| {
            p.unwrap()
                .file_name()
                .into_string()
                .unwrap()
        })
        .collect::<Vec<_>>();
    list.sort();
    list
}

fn temp_dir_and_config(
    fetch_url: &str,
    config: impl FnOnce(&TempDir, &str),
) -> (TempDir, PathBuf, SettingsBindDropGuard) {
    let temp = TempDir::new().unwrap();
    config(&temp, fetch_url);

    let mut settings = insta::Settings::clone_current();
    // remove tempdirs references
    settings.add_filter(
        &regex::escape(&temp.path().display().to_string()),
        "[TEMPDIR]",
    );

    let config_file = temp.path().join("config.toml");
    create_dir(temp.path().join("revocation")).unwrap();

    (temp, config_file, settings.bind_to_scope())
}

fn write_config(temp: &TempDir, fetch_url: &str) {
    fs::write(
        temp.path().join("config.toml"),
        format!(
            "cache-dir=\"{}\"\n\
            [revocation]\n\
            fetch-url=\"{fetch_url}revocation/\"\n",
            temp.path().display(),
        )
        .as_bytes(),
    )
    .unwrap();
}

fn apply_common_filters() -> SettingsBindDropGuard {
    let mut settings = insta::Settings::clone_current();
    // remove source locations in errors
    settings.add_filter(r"\.rs:\d+:\d+", ".rs:[LINE]:[COLUMN]");
    // remove http.server timestamps
    settings.add_filter(
        r"\d{2}/[A-Z][a-z]{2}/\d{4} \d{2}:\d{2}:\d{2}",
        "[TIMESTAMP]",
    );

    settings.bind_to_scope()
}

pub struct TestHttpServer {
    server: Arc<tiny_http::Server>,
    port: u16,
    url: String,
    handle: Option<thread::JoinHandle<String>>,
}

impl TestHttpServer {
    fn new(
        addr: (&str, u16),
        server_root: impl HttpRoot,
        conditional: bool,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let server = Arc::new(tiny_http::Server::http(addr)?);
        let addr = server
            .server_addr()
            .to_ip()
            .ok_or("server is not listening on an IP address")?;

        let thread_server = server.clone();

        let joiner = thread::spawn(move || {
            let mut log = String::new();

            for request in thread_server.incoming_requests() {
                let target = request.url().strip_prefix("/").unwrap();

                let response = match server_root.read(target) {
                    Ok((_, modified)) if conditional && not_modified(&request, modified) => {
                        tiny_http::Response::from_data(Vec::new()).with_status_code(304)
                    }
                    Ok((data, _)) => tiny_http::Response::from_data(data),
                    Err(e) => tiny_http::Response::from_string(e.to_string()).with_status_code(404),
                };
                log.push_str(&format!(
                    "{} {}  ->  {} {} ({} bytes)\n",
                    request.method(),
                    request.url(),
                    response.status_code().0,
                    response
                        .status_code()
                        .default_reason_phrase(),
                    response
                        .data_length()
                        .unwrap_or_default(),
                ));

                let _ = request.respond(response);
            }

            log
        });

        Ok(Self {
            server,
            port: addr.port(),
            url: format!("http://{addr}/"),
            handle: Some(joiner),
        })
    }

    pub fn into_log(mut self) -> String {
        self.server.unblock();
        self.handle
            .take()
            .unwrap()
            .join()
            .unwrap()
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

/// Is the resource unmodified according to the request's `If-Modified-Since` header?
///
/// A missing or unparseable header means the file is served as usual.
fn not_modified(request: &tiny_http::Request, modified: SystemTime) -> bool {
    let mut since = None;
    for header in request.headers() {
        if header.field.equiv("If-Modified-Since") {
            since = Some(header.value.as_str().to_owned());
            break;
        }
    }

    let Some(since) = since else {
        return false;
    };

    let Ok(since) = HTTP_DATE.parse_timestamp(&since) else {
        return false;
    };

    let modified = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();

    modified <= since.as_duration().unsigned_abs()
}

const HTTP_DATE: DateTimeParser = DateTimeParser::new();
