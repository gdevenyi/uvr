use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Result, UvrError};
use crate::manifest::atomic_write;

/// Top-level `uvr.lock` structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Lockfile {
    pub r: RVersionPin,

    /// Sorted alphabetically for deterministic diffs.
    #[serde(rename = "package", default)]
    pub packages: Vec<LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RVersionPin {
    pub version: String,

    /// Bioconductor release used during resolution, e.g. `"3.18"`.
    /// Only present when the lockfile includes Bioconductor packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bioc_version: Option<String>,

    /// The `exclude-newer` date (`YYYY-MM-DD`) CRAN was resolved at, from
    /// Posit Package Manager's snapshot of that day (#194). `uvr sync`
    /// takes P3M binaries from the same snapshot. Absent for a live resolve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_as_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub source: PackageSource,

    /// Raw (un-normalized) version string from the registry (e.g. `"1.1-3"`).
    /// Used to reconstruct correct tarball filenames when `url` is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_version: Option<String>,

    /// Canonical download URL. Stored so `sync` never has to reconstruct it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdirectory: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,

    /// Raw `SystemRequirements` string from DESCRIPTION, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_requirements: Option<String>,

    /// `true` if this package is only needed for development (reachable
    /// exclusively from `[dev-dependencies]`). Omitted when `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dev: bool,
}

fn is_false(v: &bool) -> bool {
    !v
}

#[derive(Debug, Clone, PartialEq)]
pub enum PackageSource {
    Cran,
    Bioconductor,
    GitHub,
    /// A Forgejo-hosted package. `host` is the bare hostname (optionally
    /// `host:port`), e.g. `"codefloe.com"`. Serializes as
    /// `"forgejo:<host>"` in the lockfile.
    Forgejo {
        host: String,
    },
    /// A GitLab-hosted package (gitlab.com or self-managed). `host` is the
    /// bare hostname (optionally `host:port`), e.g. `"gitlab.com"`.
    /// Serializes as `"gitlab:<host>"` in the lockfile.
    Gitlab {
        host: String,
    },
    Local,
    /// A custom CRAN-like repository (r-multiverse, r-universe, PPM, etc.)
    Custom {
        name: String,
    },
}

impl Serialize for PackageSource {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PackageSource {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.to_lowercase().as_str() {
            "cran" => PackageSource::Cran,
            "bioconductor" => PackageSource::Bioconductor,
            "github" => PackageSource::GitHub,
            "local" => PackageSource::Local,
            _ => {
                // `forgejo:<host>` with a non-empty host → Forgejo variant.
                // Anything else (including a bare `forgejo:`) falls through
                // to Custom so a future typo doesn't silently become a
                // valid Forgejo source with an empty host.
                if let Some(host) = s.strip_prefix("forgejo:") {
                    if !host.is_empty() {
                        return Ok(PackageSource::Forgejo {
                            host: host.to_string(),
                        });
                    }
                }
                // Same shape for `gitlab:<host>` — an empty host falls
                // through to Custom rather than a hollow Gitlab variant.
                if let Some(host) = s.strip_prefix("gitlab:") {
                    if !host.is_empty() {
                        return Ok(PackageSource::Gitlab {
                            host: host.to_string(),
                        });
                    }
                }
                PackageSource::Custom { name: s }
            }
        })
    }
}

impl std::fmt::Display for PackageSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageSource::Cran => write!(f, "cran"),
            PackageSource::Bioconductor => write!(f, "bioconductor"),
            PackageSource::GitHub => write!(f, "github"),
            PackageSource::Forgejo { host } => write!(f, "forgejo:{host}"),
            PackageSource::Gitlab { host } => write!(f, "gitlab:{host}"),
            PackageSource::Local => write!(f, "local"),
            PackageSource::Custom { name } => write!(f, "{name}"),
        }
    }
}

impl std::str::FromStr for Lockfile {
    type Err = UvrError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        toml::from_str(s).map_err(|e| UvrError::LockfileParse(e.to_string()))
    }
}

impl Lockfile {
    pub fn from_file(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        s.parse()
    }

    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(UvrError::TomlSer)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let mut sorted = self.clone();
        sorted.packages.sort_by(|a, b| a.name.cmp(&b.name));
        let s = sorted.to_toml_string()?;
        atomic_write(path, s.as_bytes())
    }

    pub fn get_package(&self, name: &str) -> Option<&LockedPackage> {
        self.packages
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
    }

    pub fn upsert_package(&mut self, pkg: LockedPackage) {
        if let Some(existing) = self.packages.iter_mut().find(|p| p.name == pkg.name) {
            *existing = pkg;
        } else {
            self.packages.push(pkg);
        }
        self.packages.sort_by(|a, b| a.name.cmp(&b.name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[r]
version = "4.3.2"

[[package]]
name = "ggplot2"
version = "3.4.4"
source = "cran"
url = "https://cran.r-project.org/src/contrib/ggplot2_3.4.4.tar.gz"
checksum = "sha256:abc123"
requires = ["dplyr", "scales"]

[[package]]
name = "dplyr"
version = "1.1.4"
source = "cran"
"#;

    #[test]
    fn round_trip() {
        let lf: Lockfile = SAMPLE.parse().expect("parse");
        assert_eq!(lf.r.version, "4.3.2");
        assert_eq!(lf.packages.len(), 2);

        let gg = lf.get_package("ggplot2").unwrap();
        assert_eq!(gg.version, "3.4.4");
        assert_eq!(
            gg.url.as_deref(),
            Some("https://cran.r-project.org/src/contrib/ggplot2_3.4.4.tar.gz")
        );
        assert_eq!(gg.requires, vec!["dplyr", "scales"]);

        let s = lf.to_toml_string().unwrap();
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }

    #[test]
    fn round_trip_with_bioc_version() {
        let input = r#"
[r]
version = "4.3.2"
bioc_version = "3.18"

[[package]]
name = "DESeq2"
version = "1.42.0"
source = "bioconductor"
url = "https://bioconductor.org/packages/3.18/bioc/src/contrib/DESeq2_1.42.0.tar.gz"
"#;
        let lf: Lockfile = input.parse().expect("parse");
        assert_eq!(lf.r.bioc_version.as_deref(), Some("3.18"));
        assert_eq!(lf.packages[0].source, PackageSource::Bioconductor);

        let s = lf.to_toml_string().unwrap();
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }

    #[test]
    fn backward_compat_no_bioc_version() {
        // Old lockfiles without bioc_version should still parse fine.
        let lf: Lockfile = SAMPLE.parse().expect("parse");
        assert!(lf.r.bioc_version.is_none());
    }

    #[test]
    fn lockfile_without_resolved_as_of_round_trips_byte_for_byte() {
        // #194 regression: a live-resolved lock gains no `resolved_as_of`.
        let lf: Lockfile = SAMPLE.parse().expect("parse");
        assert!(lf.r.resolved_as_of.is_none());
        let canonical = lf.to_toml_string().unwrap();
        assert!(!canonical.contains("resolved_as_of"));
        let reparsed: Lockfile = canonical.parse().unwrap();
        assert_eq!(reparsed.to_toml_string().unwrap(), canonical);
    }

    #[test]
    fn round_trip_with_resolved_as_of() {
        let input = "[r]\nversion = \"4.5.1\"\nresolved_as_of = \"2024-01-01\"\n\n\
                     [[package]]\nname = \"glue\"\nversion = \"1.6.2\"\nsource = \"cran\"\n\
                     url = \"https://packagemanager.posit.co/cran/2024-01-01/src/contrib/glue_1.6.2.tar.gz\"\n";
        let lf: Lockfile = input.parse().expect("parse");
        assert_eq!(lf.r.resolved_as_of.as_deref(), Some("2024-01-01"));
        assert_eq!(lf.to_toml_string().unwrap(), input);
    }

    #[test]
    fn backward_compat_no_url() {
        // Old lockfiles without `url` field should still parse
        let old = r#"
[r]
version = "4.3.2"

[[package]]
name = "ggplot2"
version = "3.4.4"
source = "cran"
"#;
        let lf: Lockfile = old.parse().unwrap();
        assert!(lf.get_package("ggplot2").unwrap().url.is_none());
    }

    #[test]
    fn round_trip_forgejo_source() {
        let input = r#"
[r]
version = "4.4.2"

[[package]]
name = "mypkg"
version = "0.1.0"
source = "forgejo:codefloe.com"
url = "https://codefloe.com/api/v1/repos/pat-s/mypkg/archive/abc123.tar.gz"
"#;
        let lf: Lockfile = input.parse().expect("parse forgejo source");
        assert_eq!(
            lf.packages[0].source,
            PackageSource::Forgejo {
                host: "codefloe.com".to_string()
            }
        );

        let s = lf.to_toml_string().unwrap();
        assert!(s.contains(r#"source = "forgejo:codefloe.com""#));
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }

    #[test]
    fn forgejo_source_empty_host_falls_to_custom() {
        // Defensive: a malformed `"forgejo:"` (empty host) deserializes
        // to Custom, not to Forgejo with an empty host string.
        let input = r#"
[r]
version = "4.4.2"

[[package]]
name = "x"
version = "0.1.0"
source = "forgejo:"
"#;
        let lf: Lockfile = input.parse().expect("parse");
        assert!(matches!(
            lf.packages[0].source,
            PackageSource::Custom { ref name } if name == "forgejo:"
        ));
    }

    #[test]
    fn round_trip_forgejo_source_with_port() {
        let input = r#"
[r]
version = "4.4.2"

[[package]]
name = "mypkg"
version = "0.1.0"
source = "forgejo:git.local:3000"
"#;
        let lf: Lockfile = input.parse().expect("parse forgejo source with port");
        assert_eq!(
            lf.packages[0].source,
            PackageSource::Forgejo {
                host: "git.local:3000".to_string()
            }
        );
        let s = lf.to_toml_string().unwrap();
        assert!(s.contains(r#"source = "forgejo:git.local:3000""#));
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }

    #[test]
    fn round_trip_gitlab_source() {
        let input = r#"
[r]
version = "4.4.2"

[[package]]
name = "mypkg"
version = "0.1.0"
source = "gitlab:gitlab.com"
url = "https://gitlab.com/api/v4/projects/group%2Fmypkg/repository/archive.tar.gz?sha=abc123"
"#;
        let lf: Lockfile = input.parse().expect("parse gitlab source");
        assert_eq!(
            lf.packages[0].source,
            PackageSource::Gitlab {
                host: "gitlab.com".to_string()
            }
        );

        let s = lf.to_toml_string().unwrap();
        assert!(s.contains(r#"source = "gitlab:gitlab.com""#));
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }

    #[test]
    fn gitlab_source_empty_host_falls_to_custom() {
        // Defensive: a malformed `"gitlab:"` (empty host) deserializes
        // to Custom, not to Gitlab with an empty host string.
        let input = r#"
[r]
version = "4.4.2"

[[package]]
name = "x"
version = "0.1.0"
source = "gitlab:"
"#;
        let lf: Lockfile = input.parse().expect("parse");
        assert!(matches!(
            lf.packages[0].source,
            PackageSource::Custom { ref name } if name == "gitlab:"
        ));
    }

    #[test]
    fn round_trip_gitlab_source_with_port() {
        let input = r#"
[r]
version = "4.4.2"

[[package]]
name = "mypkg"
version = "0.1.0"
source = "gitlab:git.local:3000"
"#;
        let lf: Lockfile = input.parse().expect("parse gitlab source with port");
        assert_eq!(
            lf.packages[0].source,
            PackageSource::Gitlab {
                host: "git.local:3000".to_string()
            }
        );
        let s = lf.to_toml_string().unwrap();
        assert!(s.contains(r#"source = "gitlab:git.local:3000""#));
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }

    #[test]
    fn round_trip_github_subdirectory() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let input = format!(
            r#"
[r]
version = "4.4.2"

[[package]]
name = "nested"
version = "0.1.0"
source = "github"
url = "https://api.github.com/repos/owner/repo/tarball/{sha}"
checksum = "git:{sha}"
subdirectory = "pkgs/nested"
"#
        );
        let lf: Lockfile = input.parse().expect("parse github subdirectory");
        let pkg = lf.get_package("nested").unwrap();
        assert_eq!(pkg.subdirectory.as_deref(), Some("pkgs/nested"));
        assert_eq!(pkg.checksum.as_deref(), Some(format!("git:{sha}").as_str()));
        assert_eq!(
            pkg.url.as_deref(),
            Some(format!("https://api.github.com/repos/owner/repo/tarball/{sha}").as_str())
        );

        let s = lf.to_toml_string().unwrap();
        assert!(s.contains(r#"subdirectory = "pkgs/nested""#));
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }

    #[test]
    fn backward_compat_no_subdirectory() {
        let lf: Lockfile = SAMPLE.parse().expect("parse");
        assert!(lf.get_package("ggplot2").unwrap().subdirectory.is_none());
        assert!(!lf.to_toml_string().unwrap().contains("subdirectory"));
    }

    #[test]
    fn round_trip_custom_source() {
        let input = r#"
[r]
version = "4.4.2"

[[package]]
name = "polars"
version = "0.20.0"
source = "community.r-multiverse.org"
url = "https://community.r-multiverse.org/src/contrib/polars_0.20.0.tar.gz"
"#;
        let lf: Lockfile = input.parse().expect("parse custom source");
        assert_eq!(
            lf.packages[0].source,
            PackageSource::Custom {
                name: "community.r-multiverse.org".to_string()
            }
        );

        // Serialize and parse back — must survive the round-trip
        let s = lf.to_toml_string().unwrap();
        assert!(s.contains(r#"source = "community.r-multiverse.org""#));
        let lf2: Lockfile = s.parse().unwrap();
        assert_eq!(lf, lf2);
    }
}
