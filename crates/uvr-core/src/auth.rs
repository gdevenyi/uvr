//! Credentials for authenticated package repositories (#185).
//!
//! A `[[sources]]` entry names a repository; its secret comes from the
//! environment, keyed by that name, or from `~/.netrc`, keyed by host
//! (#186), and never from `uvr.toml`. This is the single credential
//! resolver; the git-host tokens (#187) are meant to move behind it too.

use std::borrow::Cow;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use reqwest::StatusCode;

use crate::error::UvrError;

const TOKEN_PREFIX: &str = "UVR_REPO_TOKEN_";
const USER_PREFIX: &str = "UVR_REPO_USER_";
const PASSWORD_PREFIX: &str = "UVR_REPO_PASSWORD_";

/// A credential for one repository. `Debug` prints `Bearer ***` /
/// `Basic ***`, never the secret.
#[derive(Clone, PartialEq, Eq)]
pub enum Credential {
    Bearer(String),
    Basic { username: String, password: String },
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Credential::Bearer(_) => "Bearer ***",
            Credential::Basic { .. } => "Basic ***",
        })
    }
}

impl Credential {
    /// Set the request's `Authorization` header. reqwest marks the value
    /// sensitive, and drops it itself on a redirect to another host or port.
    pub fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Credential::Bearer(token) => req.bearer_auth(token),
            Credential::Basic { username, password } => req.basic_auth(username, Some(password)),
        }
    }
}

/// The `<NAME>` part of a repository's credential variables: drop a
/// `:port` suffix, uppercase, and turn every other non-alphanumeric
/// character into `_` (`internal-ppm` → `INTERNAL_PPM`,
/// `ppm.corp.example:8443` → `PPM_CORP_EXAMPLE`).
pub fn env_key(name: &str) -> String {
    let name = name.split_once(':').map_or(name, |(n, _port)| n);
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn read_var(prefix: &str, key: &str) -> Option<String> {
    crate::env_vars::read_env_var(&format!("{prefix}{key}")).map(|v| v.trim().to_string())
}

/// The credential for repository `name` served at `url`. First match wins:
///
/// 1. Credentials in the URL itself (`https://user:pass@host/…`): reqwest
///    sends those on its own, so this returns `None` rather than add a
///    second `Authorization` header.
/// 2. `UVR_REPO_TOKEN_<NAME>` — a bearer token.
/// 3. `UVR_REPO_USER_<NAME>` / `UVR_REPO_PASSWORD_<NAME>` — HTTP basic
///    auth; a half that is not set is sent empty.
/// 4. The netrc entry for the URL's host — HTTP basic auth.
///
/// `<NAME>` is [`env_key`]. Values are trimmed; empty or whitespace-only
/// values count as unset.
pub fn resolve(name: &str, url: &str) -> Option<Credential> {
    if has_userinfo(url) {
        return None;
    }
    env_credential(&env_key(name)).or_else(|| {
        let entry = netrc_entry(&url_host(url)?)?;
        Some(Credential::Basic {
            username: entry.login,
            password: entry.password,
        })
    })
}

fn env_credential(key: &str) -> Option<Credential> {
    if let Some(token) = read_var(TOKEN_PREFIX, key) {
        return Some(Credential::Bearer(token));
    }
    let username = read_var(USER_PREFIX, key);
    let password = read_var(PASSWORD_PREFIX, key);
    if username.is_none() && password.is_none() {
        return None;
    }
    Some(Credential::Basic {
        username: username.unwrap_or_default(),
        password: password.unwrap_or_default(),
    })
}

fn url_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()?
        .host_str()
        .map(str::to_string)
}

/// The password of the netrc entry for git host `host` (no `:port`). The
/// git hosts send it as their API token, in the header each one uses,
/// because GitLab's API does not take basic auth. The login is not used.
pub fn netrc_password(host: &str) -> Option<String> {
    netrc_entry(host)
        .map(|entry| entry.password)
        .filter(|p| !p.is_empty())
}

/// One `machine` entry of a netrc file. No `Debug`: it holds a password.
#[derive(Clone)]
struct NetrcEntry {
    machine: String,
    login: String,
    password: String,
}

/// `$NETRC`, else `~/.netrc`. On Windows, as curl does, `~/_netrc` when
/// there is no `~/.netrc`.
fn netrc_path() -> Option<PathBuf> {
    if let Some(path) = crate::env_vars::read_env_var("NETRC") {
        return Some(PathBuf::from(path));
    }
    let home = dirs::home_dir()?;
    #[cfg(windows)]
    {
        if !home.join(".netrc").exists() {
            return Some(home.join("_netrc"));
        }
    }
    Some(home.join(".netrc"))
}

/// The netrc entry for `host`, compared without case. As in curl, a
/// `machine` is a host name only and never matches a port. A `default`
/// entry is never used: it would send one credential to every repository
/// and git host.
fn netrc_entry(host: &str) -> Option<NetrcEntry> {
    // Read once per process. The key is the path so that tests can point
    // NETRC at a different file.
    static CACHE: Mutex<Option<(PathBuf, Vec<NetrcEntry>)>> = Mutex::new(None);
    let path = netrc_path()?;
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if cache.as_ref().is_none_or(|(cached, _)| *cached != path) {
        let entries = load_netrc(&path);
        *cache = Some((path, entries));
    }
    let (_, entries) = cache.as_ref()?;
    entries
        .iter()
        .find(|e| e.machine.eq_ignore_ascii_case(host))
        .cloned()
}

/// The entries of the netrc file at `path`. A missing file has none. A
/// file that other users can access (Unix), or that uvr cannot read, is
/// skipped with a warning, and the run continues without it.
fn load_netrc(path: &Path) -> Vec<NetrcEntry> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "Ignoring {}: users other than you can access it (mode {mode:o}). \
                     Run `chmod 600 {}` to use it.",
                    path.display(),
                    path.display()
                );
                return Vec::new();
            }
        }
    }
    match std::fs::read_to_string(path) {
        Ok(text) => parse_netrc(&text),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Ignoring {}: {e}", path.display());
            }
            Vec::new()
        }
    }
}

/// Parse netrc text: whitespace-separated `machine`, `login`, `password`
/// and `account` tokens; `default` (ignored, with the tokens after it);
/// `macdef` bodies (skipped to the next blank line); `#` comments; and
/// curl's double-quoted values with `\"`, `\\`, `\n`, `\r` and `\t`.
fn parse_netrc(text: &str) -> Vec<NetrcEntry> {
    let mut lexer = NetrcLexer(text);
    let mut entries = Vec::new();
    // The entry that `login` and `password` fill: none before the first
    // `machine`, and none in `default`.
    let mut current: Option<NetrcEntry> = None;
    while let Some(keyword) = lexer.keyword() {
        match keyword.as_str() {
            "machine" | "default" => {
                entries.extend(current.take());
                if keyword == "machine" {
                    current = lexer.value().map(|machine| NetrcEntry {
                        machine,
                        login: String::new(),
                        password: String::new(),
                    });
                }
            }
            "login" | "password" | "account" => {
                let value = lexer.value().unwrap_or_default();
                match (current.as_mut(), keyword.as_str()) {
                    (Some(entry), "login") => entry.login = value,
                    (Some(entry), "password") => entry.password = value,
                    _ => {}
                }
            }
            "macdef" => lexer.skip_macdef(),
            _ => {}
        }
    }
    entries.extend(current);
    entries
}

struct NetrcLexer<'a>(&'a str);

impl NetrcLexer<'_> {
    /// The next token in keyword position, after any `#` comment lines.
    fn keyword(&mut self) -> Option<String> {
        loop {
            self.0 = self.0.trim_start();
            if !self.0.starts_with('#') {
                return self.value();
            }
            self.skip_line();
        }
    }

    /// The next token: a bare word, or a double-quoted string, which ends
    /// at its closing quote or at the end of the line.
    fn value(&mut self) -> Option<String> {
        let s = self.0.trim_start();
        if s.is_empty() {
            self.0 = s;
            return None;
        }
        let Some(quoted) = s.strip_prefix('"') else {
            let end = s.find(char::is_whitespace).unwrap_or(s.len());
            self.0 = &s[end..];
            return Some(s[..end].to_string());
        };
        let mut out = String::new();
        let mut end = quoted.len();
        let mut chars = quoted.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    end = i + 1;
                    break;
                }
                '\n' => {
                    end = i;
                    break;
                }
                '\\' => match chars.next() {
                    Some((_, 'n')) => out.push('\n'),
                    Some((_, 'r')) => out.push('\r'),
                    Some((_, 't')) => out.push('\t'),
                    Some((_, c)) => out.push(c),
                    None => {}
                },
                c => out.push(c),
            }
        }
        self.0 = &quoted[end..];
        Some(out)
    }

    fn skip_line(&mut self) {
        self.0 = self.0.split_once('\n').map_or("", |(_, rest)| rest);
    }

    /// Skip a macro's name and body: all text up to the first blank line.
    fn skip_macdef(&mut self) {
        self.skip_line();
        while !self.0.is_empty() {
            let line = self.0.split_once('\n').map_or(self.0, |(line, _)| line);
            self.skip_line();
            if line.trim().is_empty() {
                break;
            }
        }
    }
}

/// Whether env var `name` holds a repository credential.
pub fn is_credential_var(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [TOKEN_PREFIX, USER_PREFIX, PASSWORD_PREFIX]
        .iter()
        .any(|p| upper.starts_with(p))
}

/// A package repository and the credential the environment gives it.
#[derive(Debug, Clone)]
pub struct Repository {
    pub name: String,
    /// Base URL, without a trailing `/`.
    pub url: String,
    pub credential: Option<Credential>,
}

impl Repository {
    pub fn new(name: &str, url: &str) -> Self {
        Repository {
            name: name.to_string(),
            url: url.trim_end_matches('/').to_string(),
            credential: resolve(name, url),
        }
    }

    /// Whether this repository serves `url`, i.e. `url` is under the
    /// repository URL. This is what keeps a credential on its own
    /// repository: a URL on any other host (or path) never gets it.
    fn serves(&self, url: &str) -> bool {
        url.strip_prefix(&self.url)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }

    /// The actionable error for a 401/403 from this repository, or `None`
    /// for any other status.
    pub fn denied_error(&self, status: StatusCode) -> Option<UvrError> {
        if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN {
            return None;
        }
        let key = env_key(&self.name);
        let head = format!(
            "repository '{}' ({}) returned HTTP {status}",
            self.name,
            redact_url(&self.url)
        );
        let host = url_host(&self.url).unwrap_or_default();
        let netrc = netrc_path().map_or_else(|| "~/.netrc".into(), |p| p.display().to_string());
        let advice = match &self.credential {
            None if has_userinfo(&self.url) => format!(
                "it refused the credentials in the repository URL. Check them, or remove them \
                 from the URL and set UVR_REPO_TOKEN_{key} instead."
            ),
            None => format!(
                "it needs credentials. Set UVR_REPO_TOKEN_{key} to a token, or \
                 UVR_REPO_USER_{key} and UVR_REPO_PASSWORD_{key} for HTTP basic auth, \
                 or add a `machine {host}` entry to {netrc}."
            ),
            // A basic credential that the environment did not give came from netrc.
            Some(Credential::Basic { .. }) if env_credential(&key).is_none() => format!(
                "it refused the login and password of the `machine {host}` entry in {netrc}. \
                 Check that they are valid, or set UVR_REPO_TOKEN_{key}, which has precedence."
            ),
            Some(Credential::Bearer(_)) => format!(
                "it refused the token in UVR_REPO_TOKEN_{key}. Check that the token is valid \
                 and gives access to this repository."
            ),
            Some(Credential::Basic { .. }) => format!(
                "it refused the credentials in UVR_REPO_USER_{key} / UVR_REPO_PASSWORD_{key}. \
                 Check that they are valid and give access to this repository."
            ),
        };
        Some(UvrError::Other(format!("{head}: {advice}")))
    }
}

/// The repository in `repos` that serves `url`. The longest repository URL
/// wins, so a repository nested under another's path keeps its own
/// credential.
pub fn repository_for<'a>(repos: &'a [Repository], url: &str) -> Option<&'a Repository> {
    repos
        .iter()
        .filter(|r| r.serves(url))
        .max_by_key(|r| r.url.len())
}

/// Byte range of the `user:password` part of `url`, if it has one.
fn userinfo_span(url: &str) -> Option<(usize, usize)> {
    let start = url.find("://")? + 3;
    let end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| start + i);
    let at = url[start..end].rfind('@')?;
    Some((start, start + at))
}

/// Whether `url` carries `user:password@` credentials.
pub fn has_userinfo(url: &str) -> bool {
    userinfo_span(url).is_some()
}

/// `url` with any `user:password@` part replaced by `***@`, for output.
pub fn redact_url(url: &str) -> Cow<'_, str> {
    match userinfo_span(url) {
        Some((start, end)) => Cow::Owned(format!("{}***{}", &url[..start], &url[end..])),
        None => Cow::Borrowed(url),
    }
}

/// Test HTTP server on `127.0.0.1`: answers each request with
/// `respond(request_head)` and records every request head it saw.
/// Not on Windows, for the loopback flakiness the CLI stub server avoids.
#[cfg(all(test, not(target_os = "windows")))]
pub(crate) fn test_server(
    respond: impl Fn(&str) -> Vec<u8> + Send + 'static,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let reply = respond(&head);
            log.lock().unwrap().push(head);
            let _ = stream.write_all(&reply);
        }
    });
    (url, seen)
}

/// An HTTP/1.1 response for [`test_server`].
#[cfg(all(test, not(target_os = "windows")))]
pub(crate) fn test_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// The `Authorization` header of a request head, if any.
#[cfg(all(test, not(target_os = "windows")))]
pub(crate) fn test_authorization(head: &str) -> Option<&str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("authorization")
            .then_some(value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VARS: &[&str] = &[
        "UVR_REPO_TOKEN_INTERNAL_PPM",
        "UVR_REPO_USER_INTERNAL_PPM",
        "UVR_REPO_PASSWORD_INTERNAL_PPM",
    ];

    fn clear() {
        for v in VARS {
            std::env::remove_var(v);
        }
    }

    #[test]
    fn env_key_normalizes_like_forgejo_hosts() {
        assert_eq!(env_key("internal-ppm"), "INTERNAL_PPM");
        assert_eq!(env_key("ppm.corp.example"), "PPM_CORP_EXAMPLE");
        assert_eq!(env_key("127.0.0.1:8443"), "127_0_0_1");
        assert_eq!(env_key("my repo/x"), "MY_REPO_X");
    }

    // One test for every env case: env vars are process-global.
    #[test]
    fn resolve_reads_env_keyed_by_repository() {
        let _env = crate::env_vars::env_lock();
        let url = "https://ppm.corp.example/cran/latest";
        clear();
        assert_eq!(resolve("internal-ppm", url), None);

        // Whitespace-only counts as unset.
        std::env::set_var("UVR_REPO_TOKEN_INTERNAL_PPM", "  ");
        assert_eq!(resolve("internal-ppm", url), None);

        std::env::set_var("UVR_REPO_USER_INTERNAL_PPM", "alice");
        std::env::set_var("UVR_REPO_PASSWORD_INTERNAL_PPM", "s3cret\n");
        assert_eq!(
            resolve("internal-ppm", url),
            Some(Credential::Basic {
                username: "alice".into(),
                password: "s3cret".into()
            })
        );

        // A token beats basic auth.
        std::env::set_var("UVR_REPO_TOKEN_INTERNAL_PPM", " tok123 ");
        assert_eq!(
            resolve("internal-ppm", url),
            Some(Credential::Bearer("tok123".into()))
        );
        // The name, not the host, keys the lookup.
        assert_eq!(resolve("other", url), None);
        // Credentials in the URL are reqwest's to send; never add a second header.
        assert_eq!(
            resolve("internal-ppm", "https://u:p@ppm.corp.example/cran"),
            None
        );

        // Only a password: basic auth with an empty user name.
        std::env::remove_var("UVR_REPO_TOKEN_INTERNAL_PPM");
        std::env::remove_var("UVR_REPO_USER_INTERNAL_PPM");
        assert_eq!(
            resolve("internal-ppm", url),
            Some(Credential::Basic {
                username: String::new(),
                password: "s3cret".into()
            })
        );
        clear();
    }

    #[test]
    fn credential_debug_is_redacted() {
        let bearer = format!("{:?}", Credential::Bearer("tok123".into()));
        let basic = format!(
            "{:?}",
            Repository {
                name: "r".into(),
                url: "https://h".into(),
                credential: Some(Credential::Basic {
                    username: "alice".into(),
                    password: "s3cret".into(),
                }),
            }
        );
        assert_eq!(bearer, "Bearer ***");
        assert!(basic.contains("Basic ***"), "{basic}");
        assert!(
            !basic.contains("alice") && !basic.contains("s3cret"),
            "{basic}"
        );
    }

    #[test]
    fn redact_url_hides_userinfo_only() {
        assert_eq!(
            redact_url("https://alice:s3cret@ppm.corp/cran/src/contrib/a_1.0.tar.gz"),
            "https://***@ppm.corp/cran/src/contrib/a_1.0.tar.gz"
        );
        assert_eq!(redact_url("http://tok@h:8080"), "http://***@h:8080");
        // An `@` in the path is not userinfo.
        let plain = "https://ppm.corp/cran/pkg@1.0?x=a@b";
        assert!(matches!(redact_url(plain), Cow::Borrowed(u) if u == plain));
        assert!(!has_userinfo(plain));
    }

    #[test]
    fn repository_for_matches_by_url_prefix() {
        let repo = |name: &str, url: &str| Repository {
            name: name.into(),
            url: url.into(),
            credential: Some(Credential::Bearer(name.into())),
        };
        let repos = [
            repo("outer", "https://ppm.corp/cran"),
            repo("inner", "https://ppm.corp/cran/internal"),
        ];
        let name = |url: &str| repository_for(&repos, url).map(|r| r.name.as_str());

        assert_eq!(
            name("https://ppm.corp/cran/src/contrib/a.tar.gz"),
            Some("outer")
        );
        assert_eq!(
            name("https://ppm.corp/cran/internal/src/contrib/a.tar.gz"),
            Some("inner")
        );
        // Another host, another port, or a sibling path never gets the credential.
        assert_eq!(name("https://cdn.example/cran/src/contrib/a.tar.gz"), None);
        assert_eq!(
            name("https://ppm.corp:8443/cran/src/contrib/a.tar.gz"),
            None
        );
        assert_eq!(
            name("https://ppm.corp/cran-public/src/contrib/a.tar.gz"),
            None
        );
        assert_eq!(name("http://ppm.corp/cran/src/contrib/a.tar.gz"), None);
    }

    #[test]
    fn denied_error_says_how_to_authenticate() {
        let mut repo = Repository {
            name: "internal-ppm".into(),
            url: "https://ppm.corp/cran".into(),
            credential: None,
        };
        assert!(repo.denied_error(StatusCode::NOT_FOUND).is_none());

        let msg = repo
            .denied_error(StatusCode::UNAUTHORIZED)
            .unwrap()
            .to_string();
        assert!(msg.contains("'internal-ppm'"), "{msg}");
        assert!(msg.contains("401 Unauthorized"), "{msg}");
        assert!(msg.contains("UVR_REPO_TOKEN_INTERNAL_PPM"), "{msg}");
        assert!(msg.contains("UVR_REPO_USER_INTERNAL_PPM"), "{msg}");

        repo.credential = Some(Credential::Bearer("tok123".into()));
        let msg = repo
            .denied_error(StatusCode::FORBIDDEN)
            .unwrap()
            .to_string();
        assert!(msg.contains("403 Forbidden"), "{msg}");
        assert!(
            msg.contains("refused the token in UVR_REPO_TOKEN_INTERNAL_PPM"),
            "{msg}"
        );
        assert!(!msg.contains("tok123"), "{msg}");

        repo.credential = None;
        repo.url = "https://alice:s3cret@ppm.corp/cran".into();
        let msg = repo
            .denied_error(StatusCode::UNAUTHORIZED)
            .unwrap()
            .to_string();
        assert!(msg.contains("credentials in the repository URL"), "{msg}");
        assert!(!msg.contains("s3cret"), "{msg}");
    }

    fn parsed(text: &str) -> Vec<(String, String, String)> {
        parse_netrc(text)
            .into_iter()
            .map(|e| (e.machine, e.login, e.password))
            .collect()
    }

    fn entry(machine: &str, login: &str, password: &str) -> (String, String, String) {
        (machine.into(), login.into(), password.into())
    }

    #[test]
    fn parse_netrc_reads_the_format() {
        let text = "# comment line\n\
            machine ppm.corp login alice password s3cret\n\
            \n\
            macdef init\n\
            machine evil.example login x password y\n\
            \n\
            machine\tgit.corp\r\n  login bob # a comment after a value\n\
            # a comment between tokens\n\
            \x20 password \"two words \\\"q\\\" #x\\\\\" account ignored\n\
            machine nopass.example login carol\n\
            machine \"quoted.example\" password \"unterminated\n\
            login dave\n\
            default login anyone password everywhere\n\
            machine last.example password";
        assert_eq!(
            parsed(text),
            vec![
                entry("ppm.corp", "alice", "s3cret"),
                // A `#` starts a comment only where a keyword can be; in
                // a value it is part of the value.
                entry("git.corp", "bob", "two words \"q\" #x\\"),
                entry("nopass.example", "carol", ""),
                entry("quoted.example", "dave", "unterminated"),
                // `default` is dropped; the file ends before a password.
                entry("last.example", "", ""),
            ]
        );
        assert!(parsed("").is_empty());
        assert!(parsed("default login a password b").is_empty());
        assert_eq!(
            parsed("macdef m\ncd /\nmachine h login l password p"),
            vec![],
            "a macro with no blank line runs to the end"
        );
    }

    /// Write `text` to a netrc file in `dir` with Unix mode `mode`.
    fn write_netrc(dir: &std::path::Path, name: &str, text: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn resolve_falls_back_to_netrc() {
        let _env = crate::env_vars::env_lock();
        clear();
        let dir = tempfile::tempdir().unwrap();
        let netrc = write_netrc(
            dir.path(),
            "netrc",
            "machine PPM.corp.example login alice password n3trc-pw\n",
            0o600,
        );
        std::env::set_var("NETRC", &netrc);
        let url = "https://ppm.corp.example:8443/cran/latest";
        let from_netrc = Some(Credential::Basic {
            username: "alice".into(),
            password: "n3trc-pw".into(),
        });

        // Keyed by host (any case, any port), not by the source name.
        assert_eq!(resolve("internal-ppm", url), from_netrc);
        assert_eq!(resolve("other", url), from_netrc);
        assert_eq!(resolve("internal-ppm", "https://cdn.example/cran"), None);
        assert_eq!(
            netrc_password("ppm.corp.example").as_deref(),
            Some("n3trc-pw")
        );
        assert_eq!(netrc_password("cdn.example"), None);
        // URL credentials still win, and no second header is added.
        assert_eq!(
            resolve("internal-ppm", "https://u:p@ppm.corp.example/cran"),
            None
        );

        // A netrc refusal names the entry, never the password.
        let repo = Repository::new("internal-ppm", url);
        let msg = repo
            .denied_error(StatusCode::UNAUTHORIZED)
            .unwrap()
            .to_string();
        assert!(
            msg.contains("`machine ppm.corp.example` entry in")
                && msg.contains(&netrc.display().to_string()),
            "{msg}"
        );
        assert!(!msg.contains("n3trc-pw") && !msg.contains("alice"), "{msg}");

        // Any env credential beats netrc.
        std::env::set_var("UVR_REPO_PASSWORD_INTERNAL_PPM", "env-pw");
        assert_eq!(
            resolve("internal-ppm", url),
            Some(Credential::Basic {
                username: String::new(),
                password: "env-pw".into()
            })
        );
        let msg = Repository::new("internal-ppm", url)
            .denied_error(StatusCode::UNAUTHORIZED)
            .unwrap()
            .to_string();
        assert!(msg.contains("UVR_REPO_PASSWORD_INTERNAL_PPM"), "{msg}");
        std::env::set_var("UVR_REPO_TOKEN_INTERNAL_PPM", "tok");
        assert_eq!(
            resolve("internal-ppm", url),
            Some(Credential::Bearer("tok".into()))
        );
        clear();

        // NETRC is read again when it names another file; the old entry is gone.
        let other = write_netrc(
            dir.path(),
            "other",
            "machine cdn.example password p\n",
            0o600,
        );
        std::env::set_var("NETRC", &other);
        assert_eq!(resolve("internal-ppm", url), None);
        assert_eq!(netrc_password("cdn.example").as_deref(), Some("p"));

        // With no entry, the refusal says how to add one.
        let msg = Repository::new("internal-ppm", url)
            .denied_error(StatusCode::UNAUTHORIZED)
            .unwrap()
            .to_string();
        assert!(
            msg.contains("add a `machine ppm.corp.example` entry to"),
            "{msg}"
        );

        // A missing file is no error.
        std::env::set_var("NETRC", dir.path().join("missing"));
        assert_eq!(resolve("internal-ppm", url), None);
        std::env::remove_var("NETRC");
    }

    #[test]
    fn git_host_tokens_fall_back_to_netrc() {
        use crate::registry::{forgejo::forgejo_token, github::github_token, gitlab::gitlab_token};

        let _env = crate::env_vars::env_lock();
        let vars = [
            "GITHUB_PAT",
            "GITHUB_TOKEN",
            "UVR_FORGEJO_TOKEN",
            "UVR_FORGEJO_TOKEN_GIT_LOCAL",
            "UVR_GITLAB_TOKEN",
            "UVR_GITLAB_TOKEN_GIT_LOCAL",
            "NETRC",
        ];
        let saved: Vec<_> = vars.iter().map(std::env::var_os).collect();
        for var in vars {
            std::env::remove_var(var);
        }
        let dir = tempfile::tempdir().unwrap();
        let netrc = write_netrc(
            dir.path(),
            "netrc",
            "machine git.local login me password pat-local\n\
             machine github.com login me password pat-github\n\
             machine nopass.local login me\n",
            0o600,
        );
        std::env::set_var("NETRC", &netrc);

        // The password is the token; a port is not part of the netrc key.
        assert_eq!(
            forgejo_token("git.local:3000").as_deref(),
            Some("pat-local")
        );
        assert_eq!(gitlab_token("git.local").as_deref(), Some("pat-local"));
        assert_eq!(github_token().as_deref(), Some("pat-github"));
        assert_eq!(forgejo_token("other.local"), None);
        assert_eq!(gitlab_token("nopass.local"), None);

        // An env token, per host or global, beats netrc.
        std::env::set_var("UVR_FORGEJO_TOKEN", "env-forgejo");
        std::env::set_var("UVR_GITLAB_TOKEN_GIT_LOCAL", "env-gitlab");
        std::env::set_var("GITHUB_TOKEN", "env-github");
        assert_eq!(forgejo_token("git.local").as_deref(), Some("env-forgejo"));
        assert_eq!(gitlab_token("git.local").as_deref(), Some("env-gitlab"));
        assert_eq!(github_token().as_deref(), Some("env-github"));

        for (var, value) in vars.iter().zip(saved) {
            match value {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn netrc_that_other_users_can_read_is_skipped() {
        let _env = crate::env_vars::env_lock();
        clear();
        let dir = tempfile::tempdir().unwrap();
        for (name, mode) in [("world", 0o644), ("group", 0o640)] {
            let path = write_netrc(
                dir.path(),
                name,
                "machine ppm.corp.example login alice password n3trc-pw\n",
                mode,
            );
            std::env::set_var("NETRC", &path);
            assert_eq!(
                resolve("internal-ppm", "https://ppm.corp.example/cran"),
                None
            );
            assert_eq!(netrc_password("ppm.corp.example"), None);
        }
        std::env::remove_var("NETRC");
    }

    #[test]
    fn credential_vars_are_recognized() {
        assert!(is_credential_var("UVR_REPO_TOKEN_X"));
        assert!(is_credential_var("UVR_REPO_USER_X"));
        assert!(is_credential_var("uvr_repo_password_x"));
        assert!(!is_credential_var("UVR_REPOS"));
        assert!(!is_credential_var("GITHUB_PAT"));
    }
}
