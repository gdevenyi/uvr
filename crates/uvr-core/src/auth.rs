//! Credentials for authenticated package repositories (#185).
//!
//! A `[[sources]]` entry names a repository; its secret comes from the
//! environment, keyed by that name, and never from `uvr.toml`. This is the
//! single credential resolver: `~/.netrc` (#186) slots in below the env
//! lookup in [`resolve`], and the git-host tokens (#187) are meant to move
//! behind it too.

use std::borrow::Cow;
use std::fmt;

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
///
/// `<NAME>` is [`env_key`]. Values are trimmed; empty or whitespace-only
/// values count as unset.
pub fn resolve(name: &str, url: &str) -> Option<Credential> {
    if has_userinfo(url) {
        return None;
    }
    let key = env_key(name);
    if let Some(token) = read_var(TOKEN_PREFIX, &key) {
        return Some(Credential::Bearer(token));
    }
    let username = read_var(USER_PREFIX, &key);
    let password = read_var(PASSWORD_PREFIX, &key);
    if username.is_none() && password.is_none() {
        return None;
    }
    Some(Credential::Basic {
        username: username.unwrap_or_default(),
        password: password.unwrap_or_default(),
    })
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
        let advice = match &self.credential {
            None if has_userinfo(&self.url) => format!(
                "it refused the credentials in the repository URL. Check them, or remove them \
                 from the URL and set UVR_REPO_TOKEN_{key} instead."
            ),
            None => format!(
                "it needs credentials. Set UVR_REPO_TOKEN_{key} to a token, or \
                 UVR_REPO_USER_{key} and UVR_REPO_PASSWORD_{key} for HTTP basic auth."
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

    #[test]
    fn credential_vars_are_recognized() {
        assert!(is_credential_var("UVR_REPO_TOKEN_X"));
        assert!(is_credential_var("UVR_REPO_USER_X"));
        assert!(is_credential_var("uvr_repo_password_x"));
        assert!(!is_credential_var("UVR_REPOS"));
        assert!(!is_credential_var("GITHUB_PAT"));
    }
}
