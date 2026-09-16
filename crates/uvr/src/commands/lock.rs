use std::collections::{HashMap, VecDeque};

use anyhow::{Context, Result};

use uvr_core::lockfile::Lockfile;
use uvr_core::manifest::DependencySpec;
use uvr_core::project::Project;
use uvr_core::r_version::detector::{find_r_binary, query_r_version};
use uvr_core::registry::bioconductor::BiocRegistry;
use uvr_core::registry::cran::CranRegistry;
use uvr_core::registry::forgejo::{
    fetch_commit_sha as fetch_forgejo_commit_sha, parse_forgejo_spec,
    resolve_forgejo_package_with_remote_entries_and_install_dependencies_at_commit_bound,
};
use uvr_core::registry::github::{
    fetch_commit_sha, parse_github_spec, resolve_github_package_with_remote_entries_at_commit_bound,
};
use uvr_core::registry::gitlab::{
    fetch_commit_sha as fetch_gitlab_commit_sha, parse_gitlab_spec,
    resolve_gitlab_package_with_remote_entries_and_install_dependencies_at_commit_bound,
};
use uvr_core::registry::{PackageInfo, RegistryChain};
use uvr_core::resolver::{PackageRegistry, Resolver};

use crate::ui;

use super::util::{build_client, make_spinner};

pub async fn run(upgrade: bool) -> Result<()> {
    let project = Project::find_cwd().context("Not inside a uvr project")?;
    let start = ui::now();
    let lockfile = resolve_and_lock(&project, upgrade).await?;
    ui::summary(
        format!("Lockfile updated — {} package(s)", lockfile.packages.len()),
        format!(
            "resolved in {}",
            ui::palette::format_duration(start.elapsed())
        ),
    );
    Ok(())
}

/// Re-resolve all dependencies and write `uvr.lock`.
/// Called by `uvr lock`, `uvr add`, and `uvr remove`.
pub async fn resolve_and_lock(project: &Project, upgrade: bool) -> Result<Lockfile> {
    let client = build_client()?;
    let existing = load_existing_lockfile(project);
    let lockfile =
        resolve_lockfile(project, &client, upgrade, existing.as_ref(), HashMap::new()).await?;
    project
        .save_lockfile(&lockfile)
        .context("Failed to write uvr.lock")?;
    Ok(lockfile)
}

/// Resolve dependencies and return the lockfile WITHOUT writing it to disk.
/// Used by `uvr sync --frozen` to verify the existing lockfile is current.
pub async fn resolve_only(project: &Project) -> Result<Lockfile> {
    let client = build_client()?;
    let existing = load_existing_lockfile(project);
    resolve_lockfile(project, &client, false, existing.as_ref(), HashMap::new()).await
}

/// Resolve with upgrade=true WITHOUT writing the lockfile.
///
/// `pins` are packages held at fixed versions, injected as pre-resolved
/// entries (they take precedence over git-resolved packages of the same
/// name). Selective `uvr update <pkg>` passes the old locked versions of
/// every non-targeted package here, so the update is validated against the
/// held-back set instead of silently producing an inconsistent lockfile
/// (#127). Pass an empty map for an unconstrained resolve (`--dry-run`).
pub async fn resolve_only_upgraded(
    project: &Project,
    pins: HashMap<String, PackageInfo>,
) -> Result<Lockfile> {
    let client = build_client()?;
    // --upgrade: don't reuse locked bioc_version, re-detect fresh
    resolve_lockfile(project, &client, true, None, pins).await
}

/// Core resolution logic shared by `resolve_and_lock` and `resolve_only`.
/// `existing` is the current lockfile on disk, used to preserve the locked
/// Bioconductor version across re-resolves (unless `upgrade` is true).
async fn resolve_lockfile(
    project: &Project,
    client: &reqwest::Client,
    upgrade: bool,
    existing: Option<&Lockfile>,
    pins: HashMap<String, PackageInfo>,
) -> Result<Lockfile> {
    // Query the actual running R version to pin in the lockfile.
    let r_constraint = project.manifest.project.r_version.as_deref();
    let r_binary_opt = find_r_binary(r_constraint).ok();
    let actual_r_version = r_binary_opt.as_deref().and_then(query_r_version);

    let spinner = make_spinner("Resolving dependencies...");

    // Determine which Bioconductor release to fetch (if any).
    let has_bioc = project.manifest.dependencies.values().any(|s| s.is_bioc())
        || project
            .manifest
            .dev_dependencies
            .values()
            .any(|s| s.is_bioc());

    let bioc_release: Option<String> = if has_bioc {
        if let Some(ref bioc_ver) = project.manifest.project.bioc_version {
            // Explicit project pin always wins — the user chose this release.
            Some(bioc_ver.clone())
        } else if upgrade {
            // --upgrade re-derives fresh from the active R, ignoring the lock.
            let r_ver = actual_r_version.as_deref().unwrap_or("4.4");
            let derived = uvr_core::registry::bioconductor::release_for_r(client, r_ver).await;
            if actual_r_version.is_none() {
                tracing::warn!(
                    "R could not be detected; Bioconductor {derived} was derived from a \
                     default of R 4.4 and may not match your project's R. Set \
                     `bioc_version` in uvr.toml to pin the release explicitly."
                );
            }
            Some(derived)
        } else if actual_r_version.is_none() {
            // R couldn't be detected, so we can't validate the locked release
            // against it — reuse the lock as-is (don't churn or warn spuriously);
            // fall back to the derived default only if there's no lock.
            match existing.and_then(|lf| lf.r.bioc_version.as_deref()) {
                Some(locked) => Some(locked.to_string()),
                None => {
                    let derived =
                        uvr_core::registry::bioconductor::release_for_r(client, "4.4").await;
                    tracing::warn!(
                        "R could not be detected and no lockfile records a Bioconductor \
                         release; Bioconductor {derived} was derived from a default of R 4.4 \
                         and may not match your project's R. Set `bioc_version` in uvr.toml \
                         to pin the release explicitly."
                    );
                    Some(derived)
                }
            }
        } else {
            let r_ver = actual_r_version.as_deref().unwrap_or("4.4");
            let derived = uvr_core::registry::bioconductor::release_for_r(client, r_ver).await;
            // Reuse the lockfile's recorded Bioc release only if it still agrees
            // with the release the active R maps to. A lock can carry a release
            // paired with a different R — R was upgraded since locking, or the
            // lock was written by an older uvr with a stale R→Bioc table (e.g.
            // R 4.6 + Bioc 3.21, #119). Honoring that pulls package sources for
            // the wrong R that fail to compile, so on mismatch we re-derive and
            // warn rather than silently reusing it.
            match existing.and_then(|lf| lf.r.bioc_version.as_deref()) {
                Some(locked) if locked == derived => Some(locked.to_string()),
                Some(locked) => {
                    tracing::warn!(
                        "Lockfile pins Bioconductor {locked}, but R {r_ver} uses Bioconductor \
                         {derived}; re-resolving against {derived} (the lockfile is updated on \
                         this run). Pin `bioc_version` in uvr.toml to force a specific release."
                    );
                    Some(derived.to_string())
                }
                None => Some(derived.to_string()),
            }
        }
    } else {
        None
    };

    // Fetch all indices in parallel: CRAN + Bioc + custom repos + git deps.
    let cran_fut = CranRegistry::fetch(client, upgrade);
    let bioc_fut = async {
        match &bioc_release {
            Some(rel) => BiocRegistry::fetch_release(client, rel)
                .await
                .map(Some)
                .context("Failed to fetch Bioconductor index"),
            None => Ok(None),
        }
    };
    let custom_fut = async {
        // Lock time only sees `uvr.toml`-declared sources. UVR_REPOS is a
        // sync-time concern (alternate binary mirrors), not a lock-time one
        // — keeping it out of lock means the lockfile stays reproducible
        // across environments with different env vars (matches #31's
        // reasoning).
        let mut regs = Vec::new();
        for source in &project.manifest.sources {
            let reg = CranRegistry::fetch_custom(client, &source.name, &source.url, upgrade, None)
                .await
                .with_context(|| {
                    format!("Failed to fetch index for repository '{}'", source.name)
                })?;
            regs.push(reg);
        }
        Ok::<_, anyhow::Error>(regs)
    };
    let git_fut = resolve_git_deps(client, &project.manifest);

    let (cran_result, bioc_result, git_result, custom_result) =
        tokio::join!(cran_fut, bioc_fut, git_fut, custom_fut,);

    let cran = cran_result.context("Failed to fetch CRAN index")?;
    let bioc_opt = bioc_result?;
    let mut pre_resolved = git_result?;
    let custom_registries: Vec<CranRegistry> = custom_result?;

    // Pins override even git-resolved entries: a non-targeted git package
    // must stay at its locked commit, not drift to a fresh HEAD (#127).
    pre_resolved.extend(pins);

    // Build the registry chain: custom sources → Bioconductor → CRAN.
    // Custom repos come first so user-configured sources take priority.
    // Bioc is placed BEFORE CRAN because CRAN's PACKAGES.gz occasionally
    // contains ghost entries for Bioc-origin packages (e.g. S4Vectors for
    // future R versions) that have no real tarball; Bioc is authoritative
    // for its own packages.
    // The resolver records the Bioconductor release in the lockfile so it's
    // fully self-describing (#153).
    let resolved_bioc = bioc_opt.as_ref().map(|b| b.release());
    let lockfile = if !custom_registries.is_empty() || bioc_opt.is_some() {
        let mut chain: Vec<&dyn PackageRegistry> = Vec::new();
        for reg in &custom_registries {
            chain.push(reg);
        }
        if let Some(ref bioc) = bioc_opt {
            chain.push(bioc);
        }
        chain.push(&cran);
        let registry = RegistryChain::new(chain);
        Resolver::new(&registry)
            .resolve(
                &project.manifest,
                actual_r_version.as_deref(),
                resolved_bioc,
                pre_resolved,
            )
            .context("Dependency resolution failed")?
    } else {
        Resolver::new(&cran)
            .resolve(
                &project.manifest,
                actual_r_version.as_deref(),
                resolved_bioc,
                pre_resolved,
            )
            .context("Dependency resolution failed")?
    };

    spinner.finish_and_clear();
    Ok(lockfile)
}

/// Load the existing lockfile, warning (not erroring) on parse failures.
/// A missing lockfile returns `None`; a corrupt lockfile logs a warning and
/// returns `None` so resolution can proceed without stale bioc pins.
fn load_existing_lockfile(project: &Project) -> Option<Lockfile> {
    match project.load_lockfile() {
        Ok(opt) => opt,
        Err(e) => {
            tracing::warn!("Failed to read existing lockfile, proceeding without it: {e}");
            None
        }
    }
}

/// Pins for a targeted upgrade (`uvr update <pkg>`, `uvr lock
/// --upgrade-package`): every locked package except `targets`, held at its
/// locked version (#127). Each target must be a direct or dev dependency; a
/// git target is simply left unpinned, so its ref re-resolves.
pub fn targeted_upgrade_pins(
    manifest: &uvr_core::manifest::Manifest,
    old: Option<&Lockfile>,
    targets: &[String],
) -> Result<HashMap<String, PackageInfo>> {
    for pkg in targets {
        if !manifest.dependencies.contains_key(pkg) && !manifest.dev_dependencies.contains_key(pkg)
        {
            anyhow::bail!(
                "Package '{}' is not in the manifest. Use `uvr add {0}` to add it.",
                pkg
            );
        }
    }
    let mut pins = HashMap::new();
    for pkg in old.map(|lf| lf.packages.as_slice()).unwrap_or_default() {
        if !targets.contains(&pkg.name) {
            pins.insert(
                pkg.name.clone(),
                uvr_core::resolver::locked_to_package_info(pkg)?,
            );
        }
    }
    Ok(pins)
}

/// `uvr lock --upgrade-package`: the lock-only half of `uvr update <pkg>`.
pub async fn run_upgrade_package(packages: Vec<String>) -> Result<()> {
    let project = Project::find_cwd().context("Not inside a uvr project")?;
    let start = ui::now();
    ui::info(format!(
        "Upgrading {} in uvr.lock",
        packages
            .iter()
            .map(|p| ui::palette::pkg(p).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let changed = upgrade_packages_in_lock(&project, &packages, |pins| {
        resolve_only_upgraded(&project, pins)
    })
    .await?;
    if changed {
        ui::summary(
            "Lockfile updated — nothing installed; run `uvr sync` to apply",
            format!(
                "resolved in {}",
                ui::palette::format_duration(start.elapsed())
            ),
        );
    }
    Ok(())
}

/// Re-resolve `packages` with everything else pinned and write `uvr.lock`
/// only if the result differs; returns whether it wrote. Never installs.
/// `resolve` turns pins into a lockfile (the network resolve in production,
/// a fixture index in tests).
async fn upgrade_packages_in_lock<F, Fut>(
    project: &Project,
    packages: &[String],
    resolve: F,
) -> Result<bool>
where
    F: FnOnce(HashMap<String, PackageInfo>) -> Fut,
    Fut: std::future::Future<Output = Result<Lockfile>>,
{
    let old = project.load_lockfile().context("Failed to read uvr.lock")?;
    let pins = targeted_upgrade_pins(&project.manifest, old.as_ref(), packages)?;
    // Without a lock there is nothing to hold back; a full resolve would
    // quietly move every package.
    let Some(old) = old else {
        anyhow::bail!("No uvr.lock to upgrade in. Run `uvr lock` first.");
    };
    let new = resolve(pins).await.with_context(|| {
        format!(
            "Targeted upgrade failed with the other packages held at their locked versions; \
             uvr.lock is unchanged. If the error above is a version conflict, the upgraded \
             package needs a newer version of a held-back dependency — upgrade that package \
             too (`uvr lock --upgrade-package {} --upgrade-package <conflicting-pkg>`) or \
             upgrade everything with `uvr lock --upgrade`.",
            packages.join(" --upgrade-package ")
        )
    })?;

    if new == old {
        ui::success("Nothing to upgrade — uvr.lock unchanged");
        return Ok(false);
    }
    for pkg in &new.packages {
        match old.get_package(&pkg.name) {
            Some(prev) if prev.version != pkg.version => {
                ui::row_upgrade(&pkg.name, &prev.version, &pkg.version)
            }
            None => ui::row_added(&pkg.name, &pkg.version),
            _ => {}
        }
    }
    for pkg in &old.packages {
        if new.get_package(&pkg.name).is_none() {
            ui::row_removed(&pkg.name, &pkg.version);
        }
    }
    project
        .save_lockfile(&new)
        .context("Failed to write uvr.lock")?;
    Ok(true)
}

/// Which registry to query for a `git = "..."` manifest value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum GitKind {
    GitHub,
    Forgejo,
    Gitlab,
}

fn classify_git(git: &str) -> GitKind {
    if git.starts_with("forgejo::") {
        GitKind::Forgejo
    } else if git.starts_with("gitlab::") {
        GitKind::Gitlab
    } else {
        GitKind::GitHub
    }
}

impl From<uvr_core::manifest::RemoteProvider> for GitKind {
    fn from(provider: uvr_core::manifest::RemoteProvider) -> Self {
        match provider {
            uvr_core::manifest::RemoteProvider::GitHub => GitKind::GitHub,
            uvr_core::manifest::RemoteProvider::Forgejo => GitKind::Forgejo,
            uvr_core::manifest::RemoteProvider::Gitlab => GitKind::Gitlab,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NameBinding {
    None,
    Exact(String),
    ParentDependencies(std::collections::BTreeSet<String>),
}

impl NameBinding {
    fn is_bound(&self) -> bool {
        !matches!(self, NameBinding::None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestOrigin {
    Manifest,
    Transitive,
}

#[derive(Debug, Clone)]
struct GitRequest {
    provider: GitKind,
    repository: String,
    requested_ref: String,
    subdirectory: Option<String>,
    binding: NameBinding,
    required: bool,
    origin: RequestOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestIdentity {
    provider: GitKind,
    repository: String,
    requested_ref: String,
    subdirectory: Option<String>,
    bound: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CommitIdentity {
    provider: GitKind,
    repository: String,
    requested_ref: String,
}

impl GitRequest {
    fn identity(&self) -> RequestIdentity {
        RequestIdentity {
            provider: self.provider,
            repository: match self.provider {
                GitKind::GitHub => self.repository.to_ascii_lowercase(),
                GitKind::Forgejo | GitKind::Gitlab => self.repository.clone(),
            },
            requested_ref: self.requested_ref.clone(),
            subdirectory: self.subdirectory.clone(),
            bound: self.binding.is_bound(),
        }
    }

    /// Build a request from a manifest `git = "..."` dependency.
    ///
    /// Fails closed when the provider/source/revision cannot be parsed: a
    /// manifest entry that declares `git` must never be dropped, because
    /// dropping it would silently resolve the name from a registry instead.
    fn direct(
        name: &str,
        git: &str,
        exact: bool,
        rev: Option<&str>,
        subdirectory: Option<&str>,
    ) -> Result<Self> {
        let spec = match rev {
            Some(rev) => format!("{git}@{rev}"),
            None => git.to_string(),
        };
        let provider = classify_git(&spec);
        let Some((repository, requested_ref)) = parse_request_spec(provider, &spec) else {
            anyhow::bail!(
                "manifest git dependency '{name}' declares an unparseable git source '{git}'{rev}; \
                 refusing registry fallback",
                rev = match rev {
                    Some(rev) => format!(" with rev '{rev}'"),
                    None => String::new(),
                }
            );
        };
        // `rsplit` always yields at least one segment; the whole repository
        // string is the right fallback for a source without a `/`.
        let canonical_name = repository.rsplit('/').next().unwrap_or(repository.as_str());
        let binding = if exact || subdirectory.is_some() || name != canonical_name {
            NameBinding::Exact(name.to_string())
        } else {
            NameBinding::None
        };
        Ok(GitRequest {
            provider,
            repository,
            requested_ref,
            subdirectory: subdirectory.map(str::to_string),
            binding,
            required: true,
            origin: RequestOrigin::Manifest,
        })
    }

    fn transitive(
        source: uvr_core::manifest::RemoteSource,
        parent_dependencies: &std::collections::BTreeSet<String>,
    ) -> Result<Self> {
        let provider = GitKind::from(source.provider);
        if source.subdirectory.is_some() && provider != GitKind::GitHub {
            anyhow::bail!(
                "Remotes entry '{}' selects a package directory on a non-GitHub target",
                source.git_spec()
            );
        }
        let binding = if source.explicit_name {
            NameBinding::Exact(source.name)
        } else if provider == GitKind::GitHub && source.subdirectory.is_some() {
            NameBinding::ParentDependencies(parent_dependencies.clone())
        } else {
            NameBinding::None
        };
        let required = binding.is_bound();
        Ok(GitRequest {
            provider,
            repository: source.repository,
            requested_ref: source.requested_ref.unwrap_or_else(|| "HEAD".to_string()),
            subdirectory: source.subdirectory,
            binding,
            required,
            origin: RequestOrigin::Transitive,
        })
    }
}

impl std::fmt::Display for GitRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.provider {
            GitKind::GitHub => write!(f, "{}@{}", self.repository, self.requested_ref)?,
            GitKind::Forgejo => write!(f, "forgejo::{}@{}", self.repository, self.requested_ref)?,
            GitKind::Gitlab => write!(f, "gitlab::{}@{}", self.repository, self.requested_ref)?,
        }
        if let Some(subdirectory) = &self.subdirectory {
            write!(f, "#subdirectory={subdirectory}")?;
        }
        Ok(())
    }
}

fn parse_request_spec(provider: GitKind, spec: &str) -> Option<(String, String)> {
    match provider {
        GitKind::GitHub => parse_github_spec(spec)
            .map(|(owner, repo, git_ref)| (format!("{owner}/{repo}"), git_ref)),
        GitKind::Forgejo => {
            let body = spec.strip_prefix("forgejo::").unwrap_or(spec);
            parse_forgejo_spec(body)
                .map(|(host, owner, repo, git_ref)| (format!("{host}/{owner}/{repo}"), git_ref))
        }
        GitKind::Gitlab => {
            let body = spec.strip_prefix("gitlab::").unwrap_or(spec);
            parse_gitlab_spec(body)
                .map(|(host, project, git_ref)| (format!("{host}/{project}"), git_ref))
        }
    }
}

/// Seed the remote walk from manifest `git = "..."` dependencies. Propagates
/// the first malformed spec instead of silently skipping it.
fn collect_git_requests(manifest: &uvr_core::manifest::Manifest) -> Result<VecDeque<GitRequest>> {
    manifest
        .dependencies
        .iter()
        .chain(manifest.dev_dependencies.iter())
        .filter_map(|(name, spec)| {
            let DependencySpec::Detailed(dep) = spec else {
                return None;
            };
            let git = dep.git.as_deref()?;
            Some(GitRequest::direct(
                name,
                git,
                dep.exact,
                dep.rev.as_deref(),
                dep.subdirectory.as_deref(),
            ))
        })
        .collect()
}

fn enqueue_remote_entries(
    queue: &mut VecDeque<GitRequest>,
    entries: Vec<uvr_core::manifest::RemoteEntry>,
    parent_dependencies: &std::collections::BTreeSet<String>,
) -> Result<()> {
    for entry in entries {
        match entry {
            uvr_core::manifest::RemoteEntry::Source(source) => {
                queue.push_back(GitRequest::transitive(source, parent_dependencies)?);
            }
            uvr_core::manifest::RemoteEntry::Unsupported {
                entry,
                reason,
                bound: true,
            } => {
                anyhow::bail!(
                    "Unsupported bound Remotes entry '{entry}': {reason}; refusing registry fallback"
                );
            }
            uvr_core::manifest::RemoteEntry::Unsupported {
                entry,
                reason,
                bound: false,
            } => tracing::warn!(
                "Ignoring unbound Remotes entry '{entry}': {reason}; falling back to registry resolution"
            ),
        }
    }
    Ok(())
}

fn ensure_bound_name(request: &GitRequest, resolved_name: &str) -> Result<()> {
    match &request.binding {
        NameBinding::None => Ok(()),
        NameBinding::Exact(expected) if expected == resolved_name => Ok(()),
        NameBinding::Exact(expected) => anyhow::bail!(
            "{} git dependency '{}' resolves to DESCRIPTION Package: '{}'; refusing registry fallback",
            match request.origin {
                RequestOrigin::Manifest => "manifest",
                RequestOrigin::Transitive => "Remotes",
            },
            expected,
            resolved_name
        ),
        NameBinding::ParentDependencies(dependencies) if dependencies.contains(resolved_name) => {
            Ok(())
        }
        NameBinding::ParentDependencies(dependencies) => {
            let dependencies = if dependencies.is_empty() {
                "none".to_string()
            } else {
                dependencies.iter().cloned().collect::<Vec<_>>().join(", ")
            };
            anyhow::bail!(
                "nested Remotes entry '{request}' resolves to DESCRIPTION Package: \
                 '{resolved_name}', which is not an install-time dependency of its parent \
                 (declared: {dependencies}); refusing registry fallback"
            )
        }
    }
}

fn commit_identity(request: &GitRequest) -> CommitIdentity {
    CommitIdentity {
        provider: request.provider,
        repository: match request.provider {
            GitKind::GitHub => request.repository.to_ascii_lowercase(),
            GitKind::Forgejo | GitKind::Gitlab => request.repository.clone(),
        },
        requested_ref: request.requested_ref.clone(),
    }
}

async fn memoized_commit<F, Fut>(
    memo: &mut HashMap<CommitIdentity, std::result::Result<String, String>>,
    key: CommitIdentity,
    fetch: F,
) -> Result<String>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = uvr_core::error::Result<String>>,
{
    if let Some(cached) = memo.get(&key) {
        return cached.clone().map_err(anyhow::Error::msg);
    }
    let fetched = fetch().await.map_err(|error| error.to_string());
    memo.insert(key, fetched.clone());
    fetched.map_err(anyhow::Error::msg)
}

/// Resolve source-chained git dependencies. Bound requests are required and
/// enforce DESCRIPTION identity; unbound root hints may fall back to registries.
/// Commit identity is memoized separately from bound resolution identity.
async fn resolve_git_deps(
    client: &reqwest::Client,
    manifest: &uvr_core::manifest::Manifest,
) -> Result<HashMap<String, PackageInfo>> {
    let mut queue = collect_git_requests(manifest)?;
    let mut pre_resolved: HashMap<String, PackageInfo> = HashMap::new();
    let mut resolved_from: HashMap<String, String> = HashMap::new();
    let mut outcomes: HashMap<RequestIdentity, std::result::Result<String, String>> =
        HashMap::new();
    let mut commit_memo: HashMap<CommitIdentity, std::result::Result<String, String>> =
        HashMap::new();

    while let Some(request) = queue.pop_front() {
        let identity = request.identity();
        if let Some(outcome) = outcomes.get(&identity) {
            match outcome {
                Ok(name) => ensure_bound_name(&request, name)?,
                Err(error) if request.required => {
                    anyhow::bail!("Failed to resolve bound git package {request}: {error}")
                }
                Err(_) => {}
            }
            continue;
        }

        let resolved: Result<_, anyhow::Error> = match request.provider {
            GitKind::GitHub => {
                let Some((owner, repo)) = request.repository.split_once('/') else {
                    anyhow::bail!("Invalid GitHub request '{request}'");
                };
                let commit_key = commit_identity(&request);
                match memoized_commit(&mut commit_memo, commit_key, || {
                    fetch_commit_sha(client, owner, repo, &request.requested_ref)
                })
                .await
                {
                    Ok(commit) => resolve_github_package_with_remote_entries_at_commit_bound(
                        client,
                        owner,
                        repo,
                        &commit,
                        request.subdirectory.as_deref(),
                        request.binding.is_bound(),
                    )
                    .await
                    .map(|(info, remotes)| {
                        let install_dependencies = info
                            .requires
                            .iter()
                            .map(|dependency| dependency.name.clone())
                            .collect();
                        (info, remotes, install_dependencies)
                    })
                    .map_err(Into::into),
                    Err(error) => Err(error),
                }
            }
            GitKind::Forgejo => {
                let parts: Vec<&str> = request.repository.split('/').collect();
                let [host, owner, repo] = parts.as_slice() else {
                    anyhow::bail!("Invalid Forgejo request '{request}'");
                };
                let commit_key = commit_identity(&request);
                match memoized_commit(&mut commit_memo, commit_key, || {
                    fetch_forgejo_commit_sha(client, host, owner, repo, &request.requested_ref)
                })
                .await
                {
                    Ok(commit) => {
                        resolve_forgejo_package_with_remote_entries_and_install_dependencies_at_commit_bound(
                            client,
                            host,
                            owner,
                            repo,
                            &commit,
                            request.binding.is_bound(),
                        )
                    }
                    .await
                    .map_err(Into::into),
                    Err(error) => Err(error),
                }
            }
            GitKind::Gitlab => {
                let Some((host, project)) = request.repository.split_once('/') else {
                    anyhow::bail!("Invalid GitLab request '{request}'");
                };
                let commit_key = commit_identity(&request);
                match memoized_commit(&mut commit_memo, commit_key, || {
                    fetch_gitlab_commit_sha(client, host, project, &request.requested_ref)
                })
                .await
                {
                    Ok(commit) => {
                        resolve_gitlab_package_with_remote_entries_and_install_dependencies_at_commit_bound(
                            client,
                            host,
                            project,
                            &commit,
                            request.binding.is_bound(),
                        )
                    }
                    .await
                    .map_err(Into::into),
                    Err(error) => Err(error),
                }
            }
        };

        let (info, remotes, parent_dependencies) = match resolved {
            Ok(resolved) => resolved,
            Err(error) => {
                let error = format!("{error:#}");
                outcomes.insert(identity, Err(error.clone()));
                if request.required {
                    anyhow::bail!("Failed to resolve bound git package {request}: {error}");
                }
                tracing::warn!(
                    "Failed to fetch unbound git Remote {request} ({error}); falling back to registry resolution"
                );
                continue;
            }
        };

        outcomes.insert(identity, Ok(info.name.clone()));
        ensure_bound_name(&request, &info.name)?;

        if let Some(existing) = pre_resolved.get(&info.name) {
            if !is_same_resolution(existing, &info) {
                let previous = resolved_from
                    .get(&info.name)
                    .map(String::as_str)
                    .unwrap_or("?");
                return Err(anyhow::anyhow!(
                    "git dependency '{name}' resolves to two different sources:\n  \
                     - {previous} → v{previous_version} ({previous_checksum}, {previous_directory})\n  \
                     - {request} → v{version} ({checksum}, {directory})\n\
                     Pin a single source/ref/subdirectory for '{name}' to disambiguate.",
                    name = info.name,
                    previous_version = existing.version,
                    previous_checksum = existing.checksum.as_deref().unwrap_or("no checksum"),
                    previous_directory = existing
                        .subdirectory
                        .as_deref()
                        .unwrap_or("repository root"),
                    version = info.version,
                    checksum = info.checksum.as_deref().unwrap_or("no checksum"),
                    directory = info
                        .subdirectory
                        .as_deref()
                        .unwrap_or("repository root"),
                ));
            }
        } else {
            resolved_from.insert(info.name.clone(), request.to_string());
            pre_resolved.insert(info.name.clone(), info);
        }

        enqueue_remote_entries(&mut queue, remotes, &parent_dependencies)?;
    }

    Ok(pre_resolved)
}

fn is_same_resolution(a: &PackageInfo, b: &PackageInfo) -> bool {
    a.version == b.version && a.checksum == b.checksum && a.subdirectory == b.subdirectory
}

#[cfg(test)]
mod tests {
    use super::*;
    use uvr_core::manifest::{RemoteEntry, RemoteProvider, RemoteSource};

    fn git_dep(git: &str, rev: Option<&str>, subdirectory: Option<&str>) -> DependencySpec {
        DependencySpec::Detailed(uvr_core::manifest::DetailedDep {
            git: Some(git.to_string()),
            rev: rev.map(str::to_string),
            subdirectory: subdirectory.map(str::to_string),
            ..Default::default()
        })
    }

    fn remote(
        name: &str,
        explicit_name: bool,
        repository: &str,
        requested_ref: Option<&str>,
        subdirectory: Option<&str>,
    ) -> RemoteEntry {
        RemoteEntry::Source(RemoteSource {
            name: name.to_string(),
            explicit_name,
            provider: RemoteProvider::GitHub,
            repository: repository.to_string(),
            requested_ref: requested_ref.map(str::to_string),
            subdirectory: subdirectory.map(str::to_string),
        })
    }

    fn package_info(version: &str, checksum: &str, subdirectory: Option<&str>) -> PackageInfo {
        PackageInfo {
            name: "nested".to_string(),
            version: semver::Version::parse(version).unwrap(),
            source: uvr_core::lockfile::PackageSource::GitHub,
            checksum: Some(checksum.to_string()),
            requires: Vec::new(),
            url: String::new(),
            raw_version: None,
            system_requirements: None,
            subdirectory: subdirectory.map(str::to_string),
        }
    }

    #[test]
    fn request_identity_includes_ref_provider_and_package_directory() {
        let make = |subdirectory: Option<&str>| GitRequest {
            provider: GitKind::GitHub,
            repository: "owner/repo".into(),
            requested_ref: "main".into(),
            subdirectory: subdirectory.map(str::to_string),
            binding: NameBinding::None,
            required: false,
            origin: RequestOrigin::Transitive,
        };
        assert_ne!(
            make(Some("pkgs/a")).identity(),
            make(Some("pkgs/b")).identity()
        );
        assert_ne!(make(Some("pkgs/a")).identity(), make(None).identity());

        let mut other_ref = make(Some("pkgs/a"));
        other_ref.requested_ref = "dev".into();
        assert_ne!(make(Some("pkgs/a")).identity(), other_ref.identity());

        let mut other_provider = make(Some("pkgs/a"));
        other_provider.provider = GitKind::Forgejo;
        assert_ne!(make(Some("pkgs/a")).identity(), other_provider.identity());

        let mut bound = make(Some("pkgs/a"));
        bound.binding = NameBinding::Exact("nested".into());
        assert_ne!(make(Some("pkgs/a")).identity(), bound.identity());
    }

    #[test]
    fn only_manifest_git_sources_seed_the_remote_walk() {
        let mut manifest = uvr_core::manifest::Manifest::new("t", None);
        manifest.add_dep(
            "registry".into(),
            DependencySpec::Version("*".into()),
            false,
        );
        manifest.add_dep(
            "nested".into(),
            git_dep("owner/repo", Some("main"), Some("pkgs/nested")),
            false,
        );
        manifest.add_dep("root".into(), git_dep("owner/root", None, None), true);

        let queue = collect_git_requests(&manifest).unwrap();
        assert_eq!(queue.len(), 2);
        assert!(queue.iter().all(|request| request.required));
        let nested = queue
            .iter()
            .find(|request| request.subdirectory.is_some())
            .unwrap();
        assert_eq!(nested.binding, NameBinding::Exact("nested".into()));
        let root = queue
            .iter()
            .find(|request| request.subdirectory.is_none())
            .unwrap();
        assert_eq!(root.binding, NameBinding::None);
    }

    #[test]
    fn malformed_manifest_git_specs_fail_closed_instead_of_seeding_an_empty_queue() {
        // A manifest key matching the repo basename used to yield an unbound
        // request, so an unparseable spec silently emptied the queue and let
        // the name resolve from a registry instead.
        let cases = [
            ("repo", "owner/repo", Some("bad ref")),
            ("aliased", "owner/repo", Some("bad ref")),
            ("root", "owner", None),
        ];
        for (name, git, rev) in cases {
            let mut manifest = uvr_core::manifest::Manifest::new("t", None);
            manifest.add_dep(name.into(), git_dep(git, rev, None), false);

            let error = collect_git_requests(&manifest)
                .expect_err("malformed git spec must not be dropped from the queue")
                .to_string();
            assert!(error.contains(name), "{error}");
            assert!(error.contains(git), "{error}");
            assert!(error.contains("refusing registry fallback"), "{error}");
            if let Some(rev) = rev {
                assert!(error.contains(rev), "{error}");
            }
        }
    }

    #[test]
    fn description_alias_bindings_survive_serialization_and_ordinary_root_stays_unbound() {
        let imported = uvr_core::manifest::Manifest::from_description_str(
            "Package: parent\nImports: Alias, repo, plain, Nested\n\
             Remotes: Alias=owner/aliased@main, repo=owner/repo, owner/plain, \
             Nested=owner/mono:packages/nested@dev\n",
        )
        .unwrap();
        let serialized = imported.to_toml_string().unwrap();
        let reparsed: uvr_core::manifest::Manifest = serialized.parse().unwrap();
        let queue = collect_git_requests(&reparsed).unwrap();

        let differing_alias = queue
            .iter()
            .find(|request| request.repository == "owner/aliased")
            .unwrap();
        assert_eq!(differing_alias.binding, NameBinding::Exact("Alias".into()));
        let same_name_alias = queue
            .iter()
            .find(|request| request.repository == "owner/repo")
            .unwrap();
        assert_eq!(same_name_alias.binding, NameBinding::Exact("repo".into()));
        let ordinary = queue
            .iter()
            .find(|request| request.repository == "owner/plain")
            .unwrap();
        assert_eq!(ordinary.binding, NameBinding::None);
        let nested = queue
            .iter()
            .find(|request| request.subdirectory.is_some())
            .unwrap();
        assert_eq!(nested.binding, NameBinding::Exact("Nested".into()));
    }

    #[test]
    fn explicit_transitive_aliases_are_exact_and_required_for_every_provider() {
        let cases = [
            (RemoteProvider::GitHub, "owner/repo"),
            (RemoteProvider::Forgejo, "code.example/team/repo"),
            (RemoteProvider::Gitlab, "gitlab.example/group/repo"),
        ];
        for (provider, repository) in cases {
            let request = GitRequest::transitive(
                RemoteSource {
                    name: "Alias".into(),
                    explicit_name: true,
                    provider,
                    repository: repository.into(),
                    requested_ref: Some("main".into()),
                    subdirectory: None,
                },
                &Default::default(),
            )
            .unwrap();
            assert_eq!(request.binding, NameBinding::Exact("Alias".into()));
            assert!(request.required);
            ensure_bound_name(&request, "Alias").unwrap();
            let error = ensure_bound_name(&request, "Actual")
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("Alias") && error.contains("Actual"),
                "{error}"
            );
        }
    }

    #[test]
    fn transitive_github_bindings_are_explicit_or_inferred_from_parent_deps() {
        let dependencies = ["actual", "other"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut queue = VecDeque::new();
        enqueue_remote_entries(
            &mut queue,
            vec![
                remote(
                    "alias",
                    true,
                    "owner/mono",
                    Some("main"),
                    Some("pkgs/component"),
                ),
                remote(
                    "component",
                    false,
                    "owner/mono",
                    Some("main"),
                    Some("pkgs/component"),
                ),
                remote("root", false, "owner/root", None, None),
            ],
            &dependencies,
        )
        .unwrap();

        assert_eq!(queue[0].binding, NameBinding::Exact("alias".into()));
        assert!(queue[0].required);
        ensure_bound_name(&queue[0], "alias").unwrap();
        assert_eq!(
            queue[1].binding,
            NameBinding::ParentDependencies(dependencies)
        );
        assert!(queue[1].required);
        assert_eq!(queue[2].binding, NameBinding::None);
        assert!(!queue[2].required);
        assert_eq!(queue[0].requested_ref, "main");
        assert_eq!(queue[0].subdirectory.as_deref(), Some("pkgs/component"));
    }

    #[test]
    fn unaliased_suggested_only_nested_remote_fails_closed() {
        let mut queue = VecDeque::new();
        enqueue_remote_entries(
            &mut queue,
            vec![remote(
                "suggested",
                false,
                "owner/mono",
                None,
                Some("pkgs/suggested"),
            )],
            &Default::default(),
        )
        .unwrap();
        let request = queue.pop_front().unwrap();
        assert!(request.required);
        assert_eq!(
            request.binding,
            NameBinding::ParentDependencies(Default::default())
        );
        let error = ensure_bound_name(&request, "suggested")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not an install-time dependency"), "{error}");
        assert!(error.contains("refusing registry fallback"), "{error}");
    }

    #[test]
    fn recursive_enqueueing_keeps_nested_github_requests_bound() {
        let mut queue = VecDeque::new();
        let first_dependencies = ["child"].into_iter().map(str::to_string).collect();
        enqueue_remote_entries(
            &mut queue,
            vec![remote(
                "child",
                false,
                "owner/mono",
                None,
                Some("pkgs/child"),
            )],
            &first_dependencies,
        )
        .unwrap();
        let child = queue.pop_front().unwrap();
        ensure_bound_name(&child, "child").unwrap();

        let child_dependencies = ["grandchild"].into_iter().map(str::to_string).collect();
        enqueue_remote_entries(
            &mut queue,
            vec![remote(
                "grandchild",
                false,
                "owner/other",
                Some("v2"),
                Some("r/grandchild"),
            )],
            &child_dependencies,
        )
        .unwrap();
        let grandchild = queue.pop_front().unwrap();
        assert_eq!(grandchild.requested_ref, "v2");
        assert_eq!(grandchild.subdirectory.as_deref(), Some("r/grandchild"));
        ensure_bound_name(&grandchild, "grandchild").unwrap();
    }

    #[test]
    fn bound_failures_and_name_mismatches_refuse_fallback() {
        let mut queue = VecDeque::new();
        let error = enqueue_remote_entries(
            &mut queue,
            vec![RemoteEntry::Unsupported {
                entry: "owner/repo/subdir#42".into(),
                reason: "pull requests are unsupported".into(),
                bound: true,
            }],
            &Default::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("refusing registry fallback"), "{error}");

        let exact = GitRequest {
            provider: GitKind::GitHub,
            repository: "owner/repo".into(),
            requested_ref: "main".into(),
            subdirectory: Some("pkgs/expected".into()),
            binding: NameBinding::Exact("expected".into()),
            required: true,
            origin: RequestOrigin::Transitive,
        };
        ensure_bound_name(&exact, "expected").unwrap();
        let error = ensure_bound_name(&exact, "actual").unwrap_err().to_string();
        assert!(
            error.contains("expected") && error.contains("actual"),
            "{error}"
        );
        assert!(error.contains("refusing registry fallback"), "{error}");

        let inferred = GitRequest {
            binding: NameBinding::ParentDependencies(
                ["actual"].into_iter().map(str::to_string).collect(),
            ),
            ..exact
        };
        ensure_bound_name(&inferred, "actual").unwrap();
        assert!(ensure_bound_name(&inferred, "other").is_err());
    }

    #[test]
    fn unsupported_unbound_root_remote_is_not_enqueued() {
        let mut queue = VecDeque::new();
        enqueue_remote_entries(
            &mut queue,
            vec![RemoteEntry::Unsupported {
                entry: "owner/repo#42".into(),
                reason: "pull requests are unsupported".into(),
                bound: false,
            }],
            &Default::default(),
        )
        .unwrap();
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn moving_ref_resolution_is_memoized_across_subdirectories() {
        let calls = std::cell::Cell::new(0usize);
        let mut memo = HashMap::new();
        let key = CommitIdentity {
            provider: GitKind::GitHub,
            repository: "owner/repo".into(),
            requested_ref: "main".into(),
        };
        let first = memoized_commit(&mut memo, key.clone(), || {
            calls.set(calls.get() + 1);
            async { Ok("commit-a".to_string()) }
        })
        .await
        .unwrap();
        let second = memoized_commit(&mut memo, key, || {
            calls.set(calls.get() + 1);
            async { Ok("commit-b".to_string()) }
        })
        .await
        .unwrap();
        assert_eq!(first, "commit-a");
        assert_eq!(second, "commit-a");
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn commit_identity_is_shared_by_bound_and_unbound_requests_for_every_provider() {
        for provider in [GitKind::GitHub, GitKind::Forgejo, GitKind::Gitlab] {
            let unbound = GitRequest {
                provider,
                repository: "host/owner/repo".into(),
                requested_ref: "main".into(),
                subdirectory: None,
                binding: NameBinding::None,
                required: false,
                origin: RequestOrigin::Transitive,
            };
            let bound = GitRequest {
                binding: NameBinding::Exact("Alias".into()),
                required: true,
                ..unbound.clone()
            };
            assert_eq!(commit_identity(&unbound), commit_identity(&bound));
            assert_ne!(unbound.identity(), bound.identity());
        }
    }

    #[test]
    fn resolutions_differing_only_by_package_directory_conflict() {
        let sha = "git:0123456789abcdef0123456789abcdef01234567";
        let a = package_info("1.0.0", sha, Some("pkgs/a"));
        assert!(is_same_resolution(
            &a,
            &package_info("1.0.0", sha, Some("pkgs/a"))
        ));
        assert!(!is_same_resolution(
            &a,
            &package_info("1.0.0", sha, Some("pkgs/b"))
        ));
        assert!(!is_same_resolution(&a, &package_info("1.0.0", sha, None)));
        assert!(!is_same_resolution(
            &a,
            &package_info("1.0.1", sha, Some("pkgs/a"))
        ));
    }

    #[test]
    fn existing_provider_classification_is_unchanged() {
        assert_eq!(classify_git("tidyverse/ggplot2"), GitKind::GitHub);
        assert_eq!(
            classify_git("forgejo::codefloe.com/pat-s/mypkg"),
            GitKind::Forgejo
        );
        assert_eq!(
            classify_git("gitlab::gitlab.com/my-group/mypkg"),
            GitKind::Gitlab
        );
    }

    // ── lock --upgrade-package (#196) ──

    const OLD_INDEX: &str = "Package: jsonlite\nVersion: 1.8.0\n\n\
        Package: shiny\nVersion: 1.0.0\nImports: rlang\n\n\
        Package: rlang\nVersion: 1.0.0\n";
    const NEW_INDEX: &str = "Package: jsonlite\nVersion: 1.9.0\n\n\
        Package: shiny\nVersion: 1.1.0\nImports: rlang\n\n\
        Package: rlang\nVersion: 1.1.0\n";

    /// Stand-in for `resolve_only_upgraded`: the same resolver, fed a
    /// fixture PACKAGES index instead of a live CRAN fetch.
    fn resolve_fixture(
        project: &Project,
        index: &str,
        pins: HashMap<String, PackageInfo>,
    ) -> Result<Lockfile> {
        let registry = CranRegistry::for_test(
            uvr_core::registry::cran::parse_packages_gz(index)?,
            "https://fixture.invalid/src/contrib".into(),
        );
        Ok(Resolver::new(&registry).resolve(&project.manifest, None, None, pins)?)
    }

    /// A project depending on jsonlite and shiny (rlang only transitively),
    /// locked against `OLD_INDEX`, with jsonlite 1.8.0 in its library.
    fn locked_project() -> (tempfile::TempDir, Project) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut manifest = uvr_core::manifest::Manifest::new("t", None);
        for name in ["jsonlite", "shiny"] {
            manifest.add_dep(name.into(), DependencySpec::Version("*".into()), false);
        }
        manifest.write(&dir.path().join("uvr.toml")).unwrap();
        let project = Project::find(dir.path()).unwrap();
        let lock = resolve_fixture(&project, OLD_INDEX, HashMap::new()).unwrap();
        project.save_lockfile(&lock).unwrap();
        let installed = project.dot_uvr_dir().join("library").join("jsonlite");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::write(installed.join("DESCRIPTION"), "Version: 1.8.0\n").unwrap();
        (dir, project)
    }

    async fn upgrade(project: &Project, target: &str, index: &str) -> Result<bool> {
        upgrade_packages_in_lock(project, &[target.to_string()], |pins| {
            std::future::ready(resolve_fixture(project, index, pins))
        })
        .await
    }

    #[tokio::test]
    async fn upgrade_package_moves_only_the_named_package_and_installs_nothing() {
        let (_dir, project) = locked_project();
        assert!(upgrade(&project, "jsonlite", NEW_INDEX).await.unwrap());

        let lock = project.load_lockfile().unwrap().unwrap();
        let version = |name| lock.get_package(name).unwrap().version.clone();
        assert_eq!(version("jsonlite"), "1.9.0");
        assert_eq!(version("shiny"), "1.0.0", "direct dep must be held");
        assert_eq!(version("rlang"), "1.0.0", "transitive dep must be held");

        let library = project.dot_uvr_dir().join("library");
        let entries: Vec<_> = std::fs::read_dir(&library)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, ["jsonlite"]);
        assert_eq!(
            std::fs::read_to_string(library.join("jsonlite").join("DESCRIPTION")).unwrap(),
            "Version: 1.8.0\n",
            "the library must not be touched"
        );
    }

    #[tokio::test]
    async fn upgrade_package_conflict_errors_and_leaves_the_lock_unchanged() {
        let (_dir, project) = locked_project();
        let before = std::fs::read(project.lock_path()).unwrap();
        // The new shiny needs a newer rlang than the held-back one.
        let index = NEW_INDEX.replace("Imports: rlang", "Imports: rlang (>= 1.1.0)");
        let err = upgrade(&project, "shiny", &index).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Version conflict for package 'rlang'"),
            "{msg}"
        );
        assert!(msg.contains("uvr.lock is unchanged"), "{msg}");
        assert_eq!(std::fs::read(project.lock_path()).unwrap(), before);
    }

    #[tokio::test]
    async fn repeated_upgrade_package_is_a_byte_identical_no_op() {
        let (_dir, project) = locked_project();
        assert!(upgrade(&project, "jsonlite", NEW_INDEX).await.unwrap());
        let before = std::fs::read(project.lock_path()).unwrap();
        assert!(!upgrade(&project, "jsonlite", NEW_INDEX).await.unwrap());
        assert_eq!(std::fs::read(project.lock_path()).unwrap(), before);
    }

    #[tokio::test]
    async fn upgrade_package_rejects_non_manifest_names_and_a_missing_lock() {
        let (_dir, project) = locked_project();
        let before = std::fs::read(project.lock_path()).unwrap();
        // Unknown, and transitive-only: `uvr update <pkg>` rejects both too.
        for name in ["nosuchpkg", "rlang"] {
            let err = upgrade(&project, name, NEW_INDEX).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("'{name}' is not in the manifest")),
                "{err}"
            );
        }
        assert_eq!(std::fs::read(project.lock_path()).unwrap(), before);

        std::fs::remove_file(project.lock_path()).unwrap();
        let err = upgrade(&project, "jsonlite", NEW_INDEX).await.unwrap_err();
        assert!(err.to_string().contains("No uvr.lock"), "{err}");
        assert!(!project.lock_path().exists());
    }
}
