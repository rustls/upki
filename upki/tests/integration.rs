// these tests won't run on windows due to insurmountable disagreements over path formatting,
// but should work ok on macOS and WSL
#![cfg(not(target_os = "windows"))]

use core::error::Error;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::{fs, thread};

use insta::assert_snapshot;
use insta::internals::SettingsBindDropGuard;
use insta_cmd::{assert_cmd_snapshot, get_cargo_bin};
use rand::Rng;
use tempfile::TempDir;

#[test]
fn version() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(upki().arg("--version"), @r"
    success: true
    exit_code: 0
    ----- stdout -----
    upki 0.1.0

    ----- stderr -----
    ");
}

#[test]
fn show_cache_dir_fixpoint() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg("/home/example/not-exist/")
            .arg("show-cache-dir"),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----
    /home/example/not-exist/

    ----- stderr -----
    ");
}

#[test]
fn verify_of_non_existent_dir() {
    let _filters = apply_common_filters();
    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg("not-exist/")
            .arg("verify"),
        @r#"
    success: false
    exit_code: 1
    ----- stdout -----

    ----- stderr -----
    Error: cannot open manifest JSON "not-exist/manifest.json"

    Caused by:
        No such file or directory (os error 2)

    Location:
        upki/src/fetch.rs:[LINE]:[COLUMN]
    "#);
}

#[test]
fn verify_of_empty_manifest() {
    let _filters = apply_common_filters();
    let (temp, _filters) = temp_dir();
    fs::write(
        temp.path().join("manifest.json"),
        include_bytes!("data/empty/manifest.json"),
    )
    .unwrap();
    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg(temp.path())
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
    let (temp, _filters) = temp_dir();
    let (server, _filters) = http_server("tests/data/empty/");

    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg(temp.path())
            .arg("fetch")
            .arg(server.url()),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @"GET /manifest.json  ->  200 OK (81 bytes)"
    );
    assert_eq!(list_dir(temp.path()), vec!["manifest.json"]);
}

#[test]
fn full_fetch() {
    let _filters = apply_common_filters();
    let (temp, _filters) = temp_dir();
    let (server, _filters) = http_server("tests/data/typical/");

    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg(temp.path())
            .arg("fetch")
            .arg(server.url()),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /manifest.json  ->  200 OK (532 bytes)
    GET /filter1.filter  ->  200 OK (11 bytes)
    GET /filter2.delta  ->  200 OK (14 bytes)
    GET /filter3.delta  ->  200 OK (10 bytes)
    ");
    assert_eq!(
        list_dir(temp.path()),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "manifest.json"
        ]
    );
}

#[test]
fn full_fetch_and_incremental_update() {
    let _filters = apply_common_filters();
    let (temp, _filters) = temp_dir();
    let (server, _filters) = http_server("tests/data/typical/");

    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg(temp.path())
            .arg("fetch")
            .arg(server.url()),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /manifest.json  ->  200 OK (532 bytes)
    GET /filter1.filter  ->  200 OK (11 bytes)
    GET /filter2.delta  ->  200 OK (14 bytes)
    GET /filter3.delta  ->  200 OK (10 bytes)
    ");
    assert_eq!(
        list_dir(temp.path()),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "manifest.json"
        ]
    );

    // now server is updated to "evolution" which requires a partial update
    // compared to "typical"
    let (server, _filters) = http_server("tests/data/evolution/");
    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg(temp.path())
            .arg("fetch")
            .arg(server.url()),
        @r"
    success: true
    exit_code: 0
    ----- stdout -----

    ----- stderr -----
    ");
    assert_snapshot!(
        server.into_log(),
        @r"
    GET /manifest.json  ->  200 OK (547 bytes)
    GET /filter4.delta  ->  200 OK (3 bytes)
    ");
    // filter2 is deleted, filter4 is new
    assert_eq!(
        list_dir(temp.path()),
        vec![
            "filter1.filter",
            "filter3.delta",
            "filter4.delta",
            "manifest.json"
        ]
    );
}

#[test]
fn typical_incremental_fetch() {
    let _filters = apply_common_filters();
    let (temp, _filters) = temp_dir();
    fs::copy(
        "tests/data/typical/manifest.json",
        temp.path().join("manifest.json"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/filter1.filter",
        temp.path().join("filter1.filter"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/filter3.delta",
        temp.path().join("filter3.delta"),
    )
    .unwrap();

    let (server, _filters) = http_server("tests/data/typical/");

    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg(temp.path())
            .arg("fetch")
            .arg(server.url()),
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
    GET /manifest.json  ->  200 OK (532 bytes)
    GET /filter2.delta  ->  200 OK (14 bytes)
    ");

    assert_eq!(
        list_dir(temp.path()),
        vec![
            "filter1.filter",
            "filter2.delta",
            "filter3.delta",
            "manifest.json"
        ]
    );
}

#[test]
fn typical_incremental_fetch_dry_run() {
    let _filters = apply_common_filters();
    let (temp, _filters) = temp_dir();
    fs::copy(
        "tests/data/typical/manifest.json",
        temp.path().join("manifest.json"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/filter1.filter",
        temp.path().join("filter1.filter"),
    )
    .unwrap();
    fs::copy(
        "tests/data/typical/filter3.delta",
        temp.path().join("filter3.delta"),
    )
    .unwrap();

    let (server, _filters) = http_server("tests/data/typical/");

    assert_cmd_snapshot!(
        upki()
            .arg("--cache-dir")
            .arg(temp.path())
            .arg("fetch")
            .arg("--dry-run")
            .arg(server.url()),
        @r#"
    success: true
    exit_code: 0
    ----- stdout -----
    2 steps required (14 bytes to download)
    - download 14 bytes from http://127.0.0.1:[PORT]/filter2.delta to "[TEMPDIR]/filter2.delta"
    - save new manifest into "[TEMPDIR]"

    ----- stderr -----
    "#);

    // fetched just the manifest
    assert_snapshot!(
        server.into_log(),
        @"GET /manifest.json  ->  200 OK (532 bytes)");

    assert_eq!(
        list_dir(temp.path()),
        vec!["filter1.filter", "filter3.delta", "manifest.json"]
    );
}

fn upki() -> Command {
    Command::new(get_cargo_bin("upki"))
}

fn http_server(root: &str) -> (TestHttpServer, SettingsBindDropGuard) {
    let port = rand::rng().random_range(4000..12000);

    // add a filter eliding the (random) port in logs
    let mut current_filters = insta::Settings::clone_current();
    current_filters.add_filter(&format!(":{port}/"), ":[PORT]/");

    (
        TestHttpServer::new(("127.0.0.1", port), Path::new(root)).unwrap(),
        current_filters.bind_to_scope(),
    )
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

fn temp_dir() -> (TempDir, SettingsBindDropGuard) {
    let temp = TempDir::new().unwrap();

    let mut settings = insta::Settings::clone_current();
    // remove tempdirs references
    settings.add_filter(
        &regex::escape(&temp.path().display().to_string()),
        "[TEMPDIR]",
    );

    (temp, settings.bind_to_scope())
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
    url: String,
    handle: Option<thread::JoinHandle<String>>,
}

impl TestHttpServer {
    pub fn new(
        addr: (&str, u16),
        server_root: &Path,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let server = Arc::new(tiny_http::Server::http(addr)?);

        let thread_server = server.clone();
        let server_root = server_root.to_owned();

        let joiner = thread::spawn(move || {
            let mut log = String::new();

            for request in thread_server.incoming_requests() {
                let target = server_root.join(request.url().strip_prefix("/").unwrap());

                let response = match fs::read(&target) {
                    Ok(data) => tiny_http::Response::from_data(data),
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
            url: format!("http://{}:{}/", addr.0, addr.1),
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
