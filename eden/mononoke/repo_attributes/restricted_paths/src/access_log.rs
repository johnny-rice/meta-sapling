/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

// Log access to restricted paths

use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use context::CoreContext;
use futures::StreamExt;
use futures::TryStreamExt;
use futures::stream;
use metaconfig_types::AclManifestMode;
use mononoke_types::NonRootMPath;
use mononoke_types::RepositoryId;
use permission_checker::AclProvider;
use permission_checker::MononokeIdentity;
use permission_checker::PermissionCheckerBuilder;
use scuba_ext::MononokeScubaSampleBuilder;
use serde_json::Value;
use serde_json::json;

use crate::ManifestId;
use crate::ManifestType;
use crate::restriction_check;

#[cfg(test)]
mod tests;

/// Result from restricted path access check — carries both authorization
/// and restriction root info for enforcement condition evaluation.
#[derive(Debug, Clone)]
pub struct RestrictionCheckResult {
    /// Whether the caller has read authorization for the restriction.
    pub has_authorization: bool,
    /// The restriction root paths matched by this access check.
    /// Empty if the path is not restricted.
    pub restriction_roots: Vec<NonRootMPath>,
}

pub const ACCESS_LOG_SCUBA_TABLE: &str = "mononoke_restricted_paths_access_test";

pub(crate) enum RestrictedPathAccessData {
    /// When the tree is accessed by manifest id
    Manifest(ManifestId, ManifestType),
    /// When the tree is accessed by path
    FullPath { full_path: NonRootMPath },
}

pub(crate) type SourceRestrictionResult =
    std::result::Result<Arc<SourceRestrictionCheckResult>, Arc<anyhow::Error>>;

/// Authorization fields that are logged at the top level of a restricted-path
/// access row.
#[derive(Clone, Copy)]
struct LoggedAuthorization {
    has_authorization: bool,
    is_allowlisted_tooling: bool,
    is_rollout_allowlisted: bool,
    has_acl_access: bool,
}

/// Top-level restriction and authorization fields for the source that controls
/// the aggregate log row.
struct RestrictedPathAggregateLogData<'a> {
    restricted_paths: Option<&'a [NonRootMPath]>,
    authorization: LoggedAuthorization,
    acls: Vec<&'a MononokeIdentity>,
}

/// Complete Scuba row payload for restricted-path access logging.
struct RestrictedPathLogData<'a> {
    repo_id: RepositoryId,
    access_data: RestrictedPathAccessData,
    aggregate: Option<RestrictedPathAggregateLogData<'a>>,
    considered_restricted_by: Vec<String>,
    source_comparison: Option<SourceComparisonLogContext>,
}

/// Extra fields emitted only when a row compares config and AclManifest source
/// results.
struct SourceComparisonLogContext {
    acl_manifest_mode: AclManifestMode,
    config_error: Option<String>,
    acl_manifest_error: Option<String>,
    shadow_mismatch: bool,
    shadow_mismatch_detail: Option<String>,
}

impl SourceComparisonLogContext {
    fn add_to_scuba(self, scuba: &mut MononokeScubaSampleBuilder) {
        scuba.add(
            "acl_manifest_mode",
            acl_manifest_mode_as_scuba_value(self.acl_manifest_mode),
        );
        if let Some(config_error) = self.config_error {
            scuba.add("config_error", config_error);
        }
        if let Some(acl_manifest_error) = self.acl_manifest_error {
            scuba.add("acl_manifest_error", acl_manifest_error);
        }
        scuba.add("shadow_mismatch", self.shadow_mismatch);
        if let Some(shadow_mismatch_detail) = self.shadow_mismatch_detail {
            scuba.add("shadow_mismatch_detail", shadow_mismatch_detail);
        }
    }
}

/// Authorization and restriction data for one logging source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceRestrictionCheckResult {
    pub(crate) has_authorization: bool,
    pub(crate) has_acl_access: bool,
    pub(crate) restriction_acls: Vec<MononokeIdentity>,
    pub(crate) restriction_paths: Option<Vec<NonRootMPath>>,
    pub(crate) is_allowlisted_tooling: bool,
    pub(crate) is_rollout_allowlisted: bool,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "implemented before Shadow dispatch wires production callers"
    )
)]
impl SourceRestrictionCheckResult {
    pub(crate) fn new(
        has_authorization: bool,
        has_acl_access: bool,
        restriction_acls: Vec<MononokeIdentity>,
        restriction_paths: Option<Vec<NonRootMPath>>,
        is_allowlisted_tooling: bool,
        is_rollout_allowlisted: bool,
    ) -> Self {
        Self {
            has_authorization,
            has_acl_access,
            restriction_acls,
            restriction_paths,
            is_allowlisted_tooling,
            is_rollout_allowlisted,
        }
    }

    pub(crate) fn unrestricted(restriction_paths: Option<Vec<NonRootMPath>>) -> Self {
        Self {
            has_authorization: true,
            has_acl_access: true,
            restriction_acls: Vec::new(),
            restriction_paths,
            is_allowlisted_tooling: false,
            is_rollout_allowlisted: false,
        }
    }

    fn is_restricted(&self) -> bool {
        !self.restriction_acls.is_empty()
    }
}

/// Check if the caller has read access to every repo region ACL in `acls`
/// (conjunctive evaluation). For nested restrictions (e.g. `/secret` plus
/// `/secret/inner`), the caller must satisfy the inner ACL even when they
/// already satisfy the outer one — otherwise being a member of an outer ACL
/// would silently bypass an inner restriction.
///
/// Runs checks concurrently and short-circuits on the first deny or error.
pub async fn has_read_access_to_repo_region_acls(
    ctx: &CoreContext,
    acl_provider: &Arc<dyn AclProvider>,
    acls: &[&MononokeIdentity],
) -> Result<bool> {
    if acls.is_empty() {
        return Ok(true);
    }

    let identities = ctx.metadata().identities();
    stream::iter(acls.iter().copied())
        .map(|acl| async move {
            let checker = acl_provider
                .repo_region_acl(acl.id_data())
                .await
                .with_context(|| {
                    format!("Failed to create PermissionChecker for {}", acl.id_data())
                })?;
            let permission_checker = PermissionCheckerBuilder::new().allow(checker).build();
            anyhow::Ok(permission_checker.check_set(identities, &["read"]).await)
        })
        .boxed()
        .buffer_unordered(acls.len())
        .try_all(futures::future::ready)
        .await
}

/// Check if the caller is a member of any of the given groups.
/// Returns true if the caller is a member of at least one group (OR logic).
/// If the groups list is empty, returns true (no restriction).
pub async fn is_member_of_groups(
    ctx: &CoreContext,
    acl_provider: &Arc<dyn AclProvider>,
    groups: &[&MononokeIdentity],
) -> Result<bool> {
    if groups.is_empty() {
        return Ok(true);
    }

    // Run all group membership checks concurrently
    let membership_results: Vec<bool> = stream::iter(groups.iter().cloned())
        .map(|group| async move {
            let membership_checker =
                acl_provider.group(group.id_data()).await.with_context(|| {
                    format!("Failed to create MembershipChecker for {}", group.id_data())
                })?;
            anyhow::Ok(
                membership_checker
                    .is_member(ctx.metadata().identities())
                    .await,
            )
        })
        .boxed()
        .buffer_unordered(groups.len())
        .try_collect()
        .await?;

    Ok(membership_results.into_iter().any(|m| m))
}

/// Check if the caller is a member of the given group.
pub async fn is_part_of_group(
    ctx: &CoreContext,
    acl_provider: &Arc<dyn AclProvider>,
    group_name: &str,
) -> Result<bool> {
    let membership_checker = acl_provider
        .group(group_name)
        .await
        .with_context(|| format!("Failed to get membership checker for group {}", group_name))?;

    Ok(membership_checker
        .is_member(ctx.metadata().identities())
        .await)
}

/// Log compact Shadow comparison results to Scuba.
///
/// This emits one row when a Shadow-mode lookup source either finds a
/// restriction or fails. Aggregate authorization fields remain
/// config-authoritative, while source disagreement is summarized with compact
/// mismatch fields. If every available source completed unrestricted, no row
/// is written.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "implemented before Shadow dispatch wires production callers"
    )
)]
pub(crate) fn log_source_results_to_scuba(
    ctx: &CoreContext,
    repo_id: RepositoryId,
    config_result: &SourceRestrictionResult,
    acl_manifest_result: Option<&SourceRestrictionResult>,
    acl_manifest_mode: AclManifestMode,
    access_data: RestrictedPathAccessData,
    scuba: MononokeScubaSampleBuilder,
) -> Result<()> {
    let Some(source_comparison) =
        source_comparison_log_context(config_result, acl_manifest_result, acl_manifest_mode)
    else {
        return Ok(());
    };

    log_access_to_scuba(
        ctx,
        RestrictedPathLogData {
            repo_id,
            access_data,
            aggregate: config_result
                .as_ref()
                .ok()
                .map(|config| RestrictedPathAggregateLogData {
                    restricted_paths: config.restriction_paths.as_deref(),
                    authorization: LoggedAuthorization {
                        has_authorization: config.has_authorization,
                        is_allowlisted_tooling: config.is_allowlisted_tooling,
                        is_rollout_allowlisted: config.is_rollout_allowlisted,
                        has_acl_access: config.has_acl_access,
                    },
                    acls: config.restriction_acls.iter().collect(),
                }),
            considered_restricted_by: considered_restricted_by_for_source_results(
                config_result,
                acl_manifest_result,
            ),
            source_comparison: Some(source_comparison),
        },
        scuba,
    )?;

    config_result
        .as_ref()
        .map(|_| ())
        .map_err(|err| anyhow::anyhow!("{:#}", err))
}

/// Build the source-comparison fields for rows that need Shadow telemetry.
///
/// Returns `None` when every source that ran completed unrestricted, matching
/// the old behavior of skipping those rows entirely.
fn source_comparison_log_context(
    config_result: &SourceRestrictionResult,
    acl_manifest_result: Option<&SourceRestrictionResult>,
    acl_manifest_mode: AclManifestMode,
) -> Option<SourceComparisonLogContext> {
    let any_source_restricted =
        is_source_restricted(Some(config_result)) || is_source_restricted(acl_manifest_result);
    let any_source_failed =
        is_source_error(Some(config_result)) || is_source_error(acl_manifest_result);
    if !any_source_restricted && !any_source_failed {
        return None;
    }

    Some(SourceComparisonLogContext {
        acl_manifest_mode,
        config_error: config_result.as_ref().err().map(|err| format!("{:#}", err)),
        acl_manifest_error: acl_manifest_result
            .and_then(|result| result.as_ref().err().map(|err| format!("{:#}", err))),
        shadow_mismatch: shadow_mismatch_for_source_results(
            Some(config_result),
            acl_manifest_result,
        ),
        shadow_mismatch_detail: shadow_mismatch_detail_for_source_results(
            config_result,
            acl_manifest_result,
        ),
    })
}

fn considered_restricted_by_for_source_results(
    config_result: &SourceRestrictionResult,
    acl_manifest_result: Option<&SourceRestrictionResult>,
) -> Vec<String> {
    let mut restricted_sources = Vec::new();
    if is_source_restricted(Some(config_result)) {
        restricted_sources.push(SourceKind::Config.as_scuba_value().to_string());
    }
    if is_source_restricted(acl_manifest_result) {
        restricted_sources.push(SourceKind::AclManifest.as_scuba_value().to_string());
    }
    restricted_sources
}

fn is_source_restricted(result: Option<&SourceRestrictionResult>) -> bool {
    matches!(result, Some(Ok(result)) if result.is_restricted())
}

fn is_source_error(result: Option<&SourceRestrictionResult>) -> bool {
    matches!(result, Some(Err(_)))
}

fn shadow_mismatch_detail_for_source_results(
    config_result: &SourceRestrictionResult,
    acl_manifest_result: Option<&SourceRestrictionResult>,
) -> Option<String> {
    let differences = shadow_mismatch_differences(config_result, acl_manifest_result);
    if differences.is_empty() {
        return None;
    }

    let mut detail = serde_json::Map::new();
    if let Some(config_detail) = source_result_detail(Some(config_result)) {
        detail.insert("config".to_string(), config_detail);
    }
    if let Some(acl_manifest_detail) = source_result_detail(acl_manifest_result) {
        detail.insert("acl_manifest".to_string(), acl_manifest_detail);
    }
    detail.insert("differences".to_string(), json!(differences));
    Some(Value::Object(detail).to_string())
}

/// Returns the queryable Shadow mismatch signal.
///
/// This marks rows that should be investigated: asymmetric source errors, or
/// successful source results that differ in restricted/unrestricted state,
/// authorization outcome, or restriction ACLs. Restriction-root differences are
/// intentionally excluded because AclManifest cannot provide roots by design;
/// they remain in `shadow_mismatch_detail` for diagnosis.
fn shadow_mismatch_for_source_results(
    config_result: Option<&SourceRestrictionResult>,
    acl_manifest_result: Option<&SourceRestrictionResult>,
) -> bool {
    let restriction_comparison = |source: SourceComparisonData| {
        (
            source.restricted,
            source.has_authorization,
            source.restriction_acls,
        )
    };

    let error_mismatch = source_error_status(config_result)
        .zip(source_error_status(acl_manifest_result))
        .is_some_and(|(config_error, acl_manifest_error)| config_error != acl_manifest_error);

    if error_mismatch {
        return true;
    }

    successful_source_result_comparison(config_result)
        .zip(successful_source_result_comparison(acl_manifest_result))
        .is_some_and(|(config, acl_manifest)| {
            restriction_comparison(config) != restriction_comparison(acl_manifest)
        })
}

fn source_error_status(result: Option<&SourceRestrictionResult>) -> Option<bool> {
    result.map(|result| result.is_err())
}

fn shadow_mismatch_differences(
    config_result: &SourceRestrictionResult,
    acl_manifest_result: Option<&SourceRestrictionResult>,
) -> Vec<&'static str> {
    let error_differences = [
        is_source_error(Some(config_result)).then_some(SourceKind::Config.error_field()),
        is_source_error(acl_manifest_result).then_some(SourceKind::AclManifest.error_field()),
    ];

    let successful_source_differences = match (
        successful_source_result_comparison(Some(config_result)),
        successful_source_result_comparison(acl_manifest_result),
    ) {
        (Some(config), Some(acl_manifest)) => [
            (config.restricted != acl_manifest.restricted, "restricted"),
            (
                config.has_authorization != acl_manifest.has_authorization,
                "has_authorization",
            ),
            (
                config.restriction_acls != acl_manifest.restriction_acls,
                "restriction_acls",
            ),
            (
                config.restriction_paths != acl_manifest.restriction_paths,
                "restriction_paths",
            ),
        ]
        .into_iter()
        .filter_map(|(is_different, field)| is_different.then_some(field))
        .collect(),
        _ => Vec::new(),
    };

    error_differences
        .into_iter()
        .flatten()
        .chain(successful_source_differences)
        .collect()
}

fn source_result_detail(result: Option<&SourceRestrictionResult>) -> Option<Value> {
    match result? {
        Ok(result) => Some(successful_source_detail(result)),
        Err(err) => Some(json!({
            "error": format!("{:#}", err),
        })),
    }
}

fn successful_source_detail(result: &SourceRestrictionCheckResult) -> Value {
    json!({
        "restricted": result.is_restricted(),
        "has_authorization": result.has_authorization,
        "restriction_acls": sorted_acls_to_strings(&result.restriction_acls),
        "restriction_paths": result
            .restriction_paths
            .as_deref()
            .map(sorted_paths_to_strings),
    })
}

fn successful_source_result_comparison(
    result: Option<&SourceRestrictionResult>,
) -> Option<SourceComparisonData> {
    let result = match result? {
        Ok(result) => result,
        Err(_) => return None,
    };
    Some(successful_source_comparison(result))
}

fn successful_source_comparison(result: &SourceRestrictionCheckResult) -> SourceComparisonData {
    SourceComparisonData {
        restricted: result.is_restricted(),
        has_authorization: result.has_authorization,
        restriction_acls: sorted_acls_to_strings(&result.restriction_acls),
        restriction_paths: result
            .restriction_paths
            .as_deref()
            .map(sorted_paths_to_strings),
    }
}

fn acls_to_strings(acls: &[MononokeIdentity]) -> Vec<String> {
    acls.iter().map(ToString::to_string).collect()
}

fn paths_to_strings(paths: &[NonRootMPath]) -> Vec<String> {
    paths.iter().map(ToString::to_string).collect()
}

fn sorted_acls_to_strings(acls: &[MononokeIdentity]) -> Vec<String> {
    let mut acls = acls_to_strings(acls);
    acls.sort();
    acls
}

fn sorted_paths_to_strings(paths: &[NonRootMPath]) -> Vec<String> {
    let mut paths = paths_to_strings(paths);
    paths.sort();
    paths
}

fn acl_manifest_mode_as_scuba_value(acl_manifest_mode: AclManifestMode) -> &'static str {
    match acl_manifest_mode {
        AclManifestMode::Disabled => "disabled",
        AclManifestMode::Shadow => "shadow",
        AclManifestMode::Both => "both",
        AclManifestMode::Authoritative => "authoritative",
    }
}

#[derive(Clone, Copy)]
enum SourceKind {
    Config,
    AclManifest,
}

impl SourceKind {
    fn error_field(self) -> &'static str {
        match self {
            Self::Config => "config_error",
            Self::AclManifest => "acl_manifest_error",
        }
    }

    fn as_scuba_value(self) -> &'static str {
        match self {
            Self::Config => "manifest_db",
            Self::AclManifest => "acl_manifest",
        }
    }
}

#[derive(Eq, PartialEq)]
struct SourceComparisonData {
    restricted: bool,
    has_authorization: bool,
    restriction_acls: Vec<String>,
    restriction_paths: Option<Vec<String>>,
}

// ============================================================================
// Schematized logger implementation (fbcode_build only)
// ============================================================================

#[cfg(fbcode_build)]
mod schematized_logger {
    use anyhow::Result;
    use context::CoreContext;
    use mononoke_restricted_paths_access_rust_logger::MononokeRestrictedPathsAccessLogger;
    use mononoke_types::NonRootMPath;
    use mononoke_types::RepositoryId;
    use permission_checker::MononokeIdentity;
    use scuba_ext::CommonMetadata;
    use scuba_ext::CommonServerData;

    use super::RestrictedPathAccessData;

    /// Log access to the schematized logger for restricted paths.
    ///
    /// This logs to both Scuba and Hive via the MononokeRestrictedPathsAccessLogger.
    pub fn log_access_to_schematized_logger(
        ctx: &CoreContext,
        repo_id: RepositoryId,
        restricted_paths: &[NonRootMPath],
        access_data: &RestrictedPathAccessData,
        has_authorization: bool,
        is_allowlisted_tooling: bool,
        is_rollout_allowlisted: bool,
        acls: &[&MononokeIdentity],
    ) -> Result<()> {
        let mut logger = MononokeRestrictedPathsAccessLogger::new(ctx.fb);

        // Add common server data using shared struct
        let server_data = CommonServerData::collect();
        apply_server_data(&mut logger, &server_data);

        // Add metadata using shared struct
        let metadata = CommonMetadata::from_metadata(ctx.metadata());
        apply_metadata(&mut logger, &metadata);

        // Set core access fields
        logger.set_repo_id(repo_id.id() as i64);
        logger.set_restricted_paths(
            restricted_paths
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
        );
        logger.set_has_authorization(has_authorization.to_string());
        logger.set_is_allowlisted_tooling(is_allowlisted_tooling.to_string());
        logger.set_is_rollout_allowlisted(is_rollout_allowlisted.to_string());
        logger.set_acls(acls.iter().map(|acl| acl.to_string()).collect::<Vec<_>>());

        // Set access data variant fields
        match access_data {
            RestrictedPathAccessData::Manifest(manifest_id, manifest_type) => {
                logger.set_manifest_id(manifest_id.to_string());
                logger.set_manifest_type(manifest_type.to_string());
            }
            RestrictedPathAccessData::FullPath { full_path } => {
                logger.set_full_path(full_path.to_string());
            }
        }

        logger.log_async()?;
        Ok(())
    }

    /// Apply CommonServerData fields to the schematized logger.
    fn apply_server_data(
        logger: &mut MononokeRestrictedPathsAccessLogger,
        data: &CommonServerData,
    ) {
        if let Some(ref hostname) = data.server_hostname {
            logger.set_server_hostname(hostname.clone());
        }
        if let Some(ref region) = data.region {
            logger.set_region(region.clone());
        }
        if let Some(ref dc) = data.datacenter {
            logger.set_datacenter(dc.clone());
        }
        if let Some(ref dc_prefix) = data.region_datacenter_prefix {
            logger.set_region_datacenter_prefix(dc_prefix.clone());
        }
        if let Some(ref tier) = data.server_tier {
            logger.set_server_tier(tier.clone());
        }
        if let Some(ref tw_task_id) = data.tw_task_id {
            logger.set_tw_task_id(tw_task_id.clone());
        }
        if let Some(ref tw_canary_id) = data.tw_canary_id {
            logger.set_tw_canary_id(tw_canary_id.clone());
        }
        if let Some(ref tw_handle) = data.tw_handle {
            logger.set_tw_handle(tw_handle.clone());
        }
        if let Some(ref tw_task_handle) = data.tw_task_handle {
            logger.set_tw_task_handle(tw_task_handle.clone());
        }
        if let Some(ref cluster) = data.chronos_cluster {
            logger.set_chronos_cluster(cluster.clone());
        }
        if let Some(ref id) = data.chronos_job_instance_id {
            logger.set_chronos_job_instance_id(id.clone());
        }
        if let Some(ref name) = data.chronos_job_name {
            logger.set_chronos_job_name(name.clone());
        }
        if let Some(ref rev) = data.build_revision {
            logger.set_build_revision(rev.clone());
        }
        if let Some(ref rule) = data.build_rule {
            logger.set_build_rule(rule.clone());
        }
    }

    /// Apply CommonMetadata fields to the schematized logger.
    fn apply_metadata(logger: &mut MononokeRestrictedPathsAccessLogger, data: &CommonMetadata) {
        logger.set_session_uuid(data.session_uuid.clone());
        logger.set_client_identities(data.client_identities.clone());

        if let Some(ref hostname) = data.source_hostname {
            logger.set_source_hostname(hostname.clone());
        }
        if let Some(ref ip) = data.client_ip {
            logger.set_client_ip(ip.clone());
        }
        if let Some(ref unix_name) = data.unix_username {
            logger.set_unix_username(unix_name.clone());
        }
        if let Some(ref main_id) = data.client_main_id {
            logger.set_client_main_id(main_id.clone());
        }
        if let Some(ref entry_point) = data.client_entry_point {
            logger.set_client_entry_point(entry_point.clone());
        }
        if let Some(ref correlator) = data.client_correlator {
            logger.set_client_correlator(correlator.clone());
        }
        if !data.enabled_experiments_jk.is_empty() {
            logger.set_enabled_experiments_jk(data.enabled_experiments_jk.clone());
        }
        if let Some(ref alias) = data.sandcastle_alias {
            logger.set_sandcastle_alias(alias.clone());
        }
        if let Some(ref vcs) = data.sandcastle_vcs {
            logger.set_sandcastle_vcs(vcs.clone());
        }
        if let Some(ref region) = data.revproxy_region {
            logger.set_revproxy_region(region.clone());
        }
        if let Some(ref nonce) = data.sandcastle_nonce {
            logger.set_sandcastle_nonce(nonce.clone());
        }
        if let Some(ref tw_job) = data.client_tw_job {
            logger.set_client_tw_job(tw_job.clone());
        }
        if let Some(ref tw_task) = data.client_tw_task {
            logger.set_client_tw_task(tw_task.clone());
        }
        if let Some(ref atlas) = data.client_atlas {
            logger.set_client_atlas(atlas.clone());
        }
        if let Some(ref env_id) = data.client_atlas_env_id {
            logger.set_client_atlas_env_id(env_id.clone());
        }
        if let Some(ref cause) = data.fetch_cause {
            logger.set_fetch_cause(cause.clone());
        }
        logger.set_fetch_from_cas_attempted(data.fetch_from_cas_attempted);
    }
}

pub(crate) async fn log_access_to_restricted_path(
    ctx: &CoreContext,
    repo_id: RepositoryId,
    restricted_paths: Vec<NonRootMPath>,
    acls: Vec<&MononokeIdentity>,
    access_data: RestrictedPathAccessData,
    acl_provider: Arc<dyn AclProvider>,
    tooling_allowlist_group: Option<&str>,
    rollout_allowlist_group: Option<&str>,
    scuba: MononokeScubaSampleBuilder,
    considered_restricted_by: Vec<String>,
) -> Result<RestrictionCheckResult> {
    let authorization = restriction_check::check_authorization(
        ctx,
        &acl_provider,
        &acls,
        tooling_allowlist_group,
        rollout_allowlist_group,
    )
    .await?;

    let result = restriction_check::build_restriction_check_result(
        authorization.has_authorization(),
        restricted_paths.clone(),
    );
    log_checked_access_to_restricted_path(
        ctx,
        RestrictedPathLogData {
            repo_id,
            access_data,
            aggregate: Some(RestrictedPathAggregateLogData {
                restricted_paths: Some(&restricted_paths),
                authorization: LoggedAuthorization {
                    has_authorization: authorization.has_authorization(),
                    is_allowlisted_tooling: authorization.is_allowlisted_tooling,
                    is_rollout_allowlisted: authorization.is_rollout_allowlisted,
                    has_acl_access: authorization.has_acl_access,
                },
                acls,
            }),
            considered_restricted_by,
            source_comparison: None,
        },
        scuba,
    )?;

    Ok(result)
}

fn log_checked_access_to_restricted_path(
    ctx: &CoreContext,
    log_data: RestrictedPathLogData<'_>,
    scuba: MononokeScubaSampleBuilder,
) -> Result<()> {
    // Override sampling for unauthorized SCSC accesses to restricted paths
    #[cfg(fbcode_build)]
    {
        use clientinfo::ClientEntryPoint;

        let is_scsc = ctx
            .metadata()
            .client_request_info()
            .is_some_and(|cri| cri.entry_point == ClientEntryPoint::ScsClient);

        if let Some(aggregate) = log_data.aggregate.as_ref()
            && is_scsc
            && !aggregate.authorization.has_authorization
        {
            ctx.set_override_sampling();
        }
    }

    // Log to schematized logger (logs to both Scuba and Hive) if enabled via JK
    // Only available in fbcode builds
    #[cfg(fbcode_build)]
    {
        let use_schematized_logger = justknobs::eval(
            "scm/mononoke:restricted_paths_use_schematized_logger",
            None,
            None,
        )?;

        if let Some(aggregate) = log_data.aggregate.as_ref()
            && use_schematized_logger
        {
            if let Err(e) = schematized_logger::log_access_to_schematized_logger(
                ctx,
                log_data.repo_id,
                aggregate.restricted_paths.unwrap_or(&[]),
                &log_data.access_data,
                aggregate.authorization.has_authorization,
                aggregate.authorization.is_allowlisted_tooling,
                aggregate.authorization.is_rollout_allowlisted,
                &aggregate.acls,
            ) {
                tracing::error!("Failed to log to schematized logger: {:?}", e);
            }
        }
    }

    log_access_to_scuba(ctx, log_data, scuba)
}

fn log_access_to_scuba(
    ctx: &CoreContext,
    log_data: RestrictedPathLogData<'_>,
    mut scuba: MononokeScubaSampleBuilder,
) -> Result<()> {
    scuba.add_metadata(ctx.metadata());

    scuba.add_common_server_data();

    // We want to log all samples
    scuba.unsampled();

    scuba.add("repo_id", log_data.repo_id.id());

    if let Some(aggregate) = log_data.aggregate {
        if let Some(restricted_paths) = aggregate.restricted_paths {
            scuba.add("restricted_paths", paths_to_strings(restricted_paths));
        }
        scuba.add(
            "has_authorization",
            aggregate.authorization.has_authorization,
        );
        scuba.add(
            "is_allowlisted_tooling",
            aggregate.authorization.is_allowlisted_tooling,
        );
        scuba.add(
            "is_rollout_allowlisted",
            aggregate.authorization.is_rollout_allowlisted,
        );
        scuba.add("has_acl_access", aggregate.authorization.has_acl_access);
        scuba.add(
            "acls",
            aggregate
                .acls
                .into_iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );
    }

    // Log access data based on the type
    match log_data.access_data {
        RestrictedPathAccessData::Manifest(manifest_id, manifest_type) => {
            scuba.add("manifest_id", manifest_id.to_string());
            scuba.add("manifest_type", manifest_type.to_string());
        }
        RestrictedPathAccessData::FullPath { full_path, .. } => {
            scuba.add("full_path", full_path.to_string());
        }
    }

    scuba.add(
        "considered_restricted_by",
        log_data.considered_restricted_by,
    );
    if let Some(source_comparison) = log_data.source_comparison {
        source_comparison.add_to_scuba(&mut scuba);
    }

    scuba.log();

    Ok(())
}
