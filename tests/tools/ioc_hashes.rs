//! Run against the certified Rustinel source tree as documented in docs/ioc-policy.md.

use std::{env, path::PathBuf};

use rustinel::config::IocConfig;
use rustinel::ioc::{ComputedHashes, IocEngine, IocKind};
use rustinel::models::Provenance;
use rustinel::vocab::Platform;

#[test]
fn published_driver_digest_matches_windows_advanced() {
    const RTCORE64_SHA256: &str =
        "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd";
    let feeds = PathBuf::from(env::var_os("RUSTINEL_RULES_DIST").expect("set RUSTINEL_RULES_DIST"))
        .join("windows-advanced/ioc");
    let engine = IocEngine::try_load(&IocConfig {
        enabled: true,
        hashes_path: feeds.join("hashes.txt"),
        ips_path: feeds.join("ips.txt"),
        domains_path: feeds.join("domains.txt"),
        paths_regex_path: feeds.join("paths_regex.txt"),
        default_severity: "high".into(),
        max_file_size_mb: 50,
        hash_allowlist_paths: Vec::new(),
    })
    .expect("load the Windows Advanced IOC feeds");

    let mut hashes = ComputedHashes {
        sha256: Some(RTCORE64_SHA256.into()),
        md5: None,
        sha1: None,
    };
    let matches = engine.match_hashes(&hashes);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].kind, IocKind::Sha256);
    assert_eq!(matches[0].indicator, RTCORE64_SHA256);
    let alert = engine.build_alert_for_hash_match(
        &matches[0],
        r"C:\Windows\System32\drivers\RTCore64.sys",
        42,
        &Provenance::default(),
        Platform::Windows,
        "etw",
    );
    assert_eq!(alert.rule_name, format!("ioc:sha256:{RTCORE64_SHA256}"));
    assert!(alert
        .rule_description
        .as_deref()
        .unwrap()
        .starts_with("[ioc-loldrivers-vulnerable-hashes] RTCore64.sys"));

    hashes.sha256.as_mut().unwrap().replace_range(..1, "f");
    assert!(engine.match_hashes(&hashes).is_empty());
}
