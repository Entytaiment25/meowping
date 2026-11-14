use std::fmt::Write;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

const TTL_SECS: u64 = 7 * 24 * 60 * 60;

type Entries = Vec<(IpAddr, u64, String)>;

struct Cache {
    path: Option<PathBuf>,
    entries: Entries,
}

static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

fn cache() -> &'static Mutex<Cache> {
    CACHE.get_or_init(|| {
        let path = cache_dir().map(|dir| dir.join("meowping").join("asn.cache"));
        let entries = path.as_deref().map_or_else(Vec::new, |p| load(p, now()));
        Mutex::new(Cache { path, entries })
    })
}

pub fn get(ip: IpAddr) -> Option<String> {
    let cache = cache().lock().unwrap_or_else(PoisonError::into_inner);
    cache
        .entries
        .iter()
        .find(|entry| entry.0 == ip)
        .map(|entry| entry.2.clone())
}

pub fn put(ip: IpAddr, org: &str) {
    if org.contains(['\t', '\n', '\r']) {
        return;
    }
    let mut cache = cache().lock().unwrap_or_else(PoisonError::into_inner);
    upsert(&mut cache.entries, ip, now(), org);
    if let Some(path) = &cache.path {
        save(path, &cache.entries);
    }
}

fn upsert(entries: &mut Entries, ip: IpAddr, stored: u64, org: &str) {
    if let Some(entry) = entries.iter_mut().find(|entry| entry.0 == ip) {
        *entry = (ip, stored, org.to_string());
    } else {
        entries.push((ip, stored, org.to_string()));
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(target_os = "macos")]
fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library").join("Caches"))
}

#[cfg(windows)]
fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
}

fn load(path: &Path, now: u64) -> Entries {
    let mut entries = Entries::new();
    let Ok(content) = fs::read_to_string(path) else {
        return entries;
    };
    for line in content.lines() {
        let mut parts = line.splitn(3, '\t');
        let (Some(ip), Some(stored), Some(org)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if let (Ok(ip), Ok(stored)) = (ip.parse(), stored.parse::<u64>())
            && now.saturating_sub(stored) < TTL_SECS
        {
            upsert(&mut entries, ip, stored, org);
        }
    }
    entries
}

fn save(path: &Path, entries: &Entries) {
    let Some(dir) = path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let mut content = String::new();
    for (ip, stored, org) in entries {
        let _ = writeln!(content, "{ip}\t{stored}\t{org}");
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    if fs::write(&tmp, content).is_err() || fs::rename(&tmp, path).is_err() {
        let _ = fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("meowping-test-{}-{name}", std::process::id()))
            .join("asn.cache")
    }

    #[test]
    fn saved_entries_load_back() {
        let path = temp_path("roundtrip");
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let entries = vec![(ip, 1_000, "AS13335 Cloudflare, Inc.".to_string())];
        save(&path, &entries);
        assert_eq!(load(&path, 1_000 + 60), entries);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn expired_and_malformed_entries_are_dropped() {
        let path = temp_path("expired");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "1.1.1.1\t100\tAS13335 Cloudflare, Inc.\nnot an entry\n8.8.8.8\tabc\tAS15169\n",
        )
        .unwrap();
        assert_eq!(load(&path, 100 + TTL_SECS).len(), 0);
        assert_eq!(load(&path, 100 + TTL_SECS - 1).len(), 1);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn missing_file_loads_empty() {
        assert_eq!(load(&temp_path("missing"), 0).len(), 0);
    }
}
