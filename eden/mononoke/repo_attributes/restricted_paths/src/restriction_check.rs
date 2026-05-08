/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

//! Restriction check helpers that turn restriction lookup results into
//! authorization results.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use context::CoreContext;
use futures::future;
use mononoke_types::ChangesetId;
use mononoke_types::NonRootMPath;
use permission_checker::AclProvider;
use permission_checker::MononokeIdentity;

use crate::ManifestId;
use crate::ManifestType;
use crate::RestrictedPaths;
use crate::access_log::SourceRestrictionCheckResult;
use crate::access_log::has_read_access_to_repo_region_acls;
use crate::access_log::is_part_of_group;
use crate::restriction_info;
use crate::restriction_info::ManifestRestrictionInfo;
use crate::restriction_info::PathRestrictionInfo;

/// Source to use for path-side restriction checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PathRestrictionSource {
    /// Config-backed path ACLs.
    Config,
    /// AclManifest at a specific changeset.
    AclManifest(ChangesetId),
}

/// Source to use for manifest-side restriction checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManifestRestrictionSource {
    /// Config-backed manifest-id store.
    Config,
    /// AclManifest pointer attached to the manifest.
    AclManifest,
}

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

/// Authorization flags produced by evaluating the caller against one source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizationCheckResult {
    /// Whether the caller has direct read access to every matching path ACL.
    has_acl_access: bool,
    /// Whether the caller is in the tooling allowlist group.
    is_allowlisted_tooling: bool,
    /// Whether the caller is in the rollout allowlist group.
    is_rollout_allowlisted: bool,
}

impl AuthorizationCheckResult {
    /// Whether the caller has read authorization through ACLs or allowlists.
    pub(crate) fn has_authorization(&self) -> bool {
        self.has_acl_access || self.is_allowlisted_tooling || self.is_rollout_allowlisted
    }

    pub(crate) fn has_acl_access(&self) -> bool {
        self.has_acl_access
    }

    pub(crate) fn is_allowlisted_tooling(&self) -> bool {
        self.is_allowlisted_tooling
    }

    pub(crate) fn is_rollout_allowlisted(&self) -> bool {
        self.is_rollout_allowlisted
    }
}

/// Evaluate ACL and allowlist authorization for a restricted-path access.
pub(crate) async fn check_authorization(
    ctx: &CoreContext,
    acl_provider: &Arc<dyn AclProvider>,
    acls: &[&MononokeIdentity],
    tooling_allowlist_group: Option<&str>,
    rollout_allowlist_group: Option<&str>,
) -> Result<AuthorizationCheckResult> {
    let has_acl_access = has_read_access_to_repo_region_acls(ctx, acl_provider, acls).await?;
    let is_allowlisted_tooling = tooling_allowlist_group
        .map_or(future::Either::Left(future::ok(false)), |group_name| {
            future::Either::Right(is_part_of_group(ctx, acl_provider, group_name))
        })
        .await?;
    let is_rollout_allowlisted = rollout_allowlist_group
        .map_or(future::Either::Left(future::ok(false)), |group_name| {
            future::Either::Right(is_part_of_group(ctx, acl_provider, group_name))
        })
        .await?;

    Ok(AuthorizationCheckResult {
        has_acl_access,
        is_allowlisted_tooling,
        is_rollout_allowlisted,
    })
}

/// Build the legacy restricted-path check result shape.
pub(crate) fn build_restriction_check_result(
    has_authorization: bool,
    restriction_roots: Vec<NonRootMPath>,
) -> RestrictionCheckResult {
    RestrictionCheckResult {
        has_authorization,
        restriction_roots,
    }
}

/// Check a path against one restriction source.
pub(crate) async fn check_path_restriction(
    ctx: &CoreContext,
    restricted_paths: &RestrictedPaths,
    path: NonRootMPath,
    source: PathRestrictionSource,
) -> Result<SourceRestrictionCheckResult> {
    match source {
        PathRestrictionSource::Config => {
            check_config_path_authorization(ctx, restricted_paths, &path).await
        }
        PathRestrictionSource::AclManifest(cs_id) => {
            let restriction_info = restriction_info::get_path_restriction_info_from_acl_manifest(
                restricted_paths,
                ctx,
                cs_id,
                std::slice::from_ref(&path),
            )
            .await
            .context("find AclManifest restrictions for path-side fetch")?;
            let restriction_acls = parse_restriction_acls(&restriction_info)?;
            check_path_authorization(ctx, restricted_paths, restriction_info, restriction_acls)
                .await
        }
    }
}

/// Check a manifest against one restriction source.
pub(crate) async fn check_manifest_restriction(
    ctx: &CoreContext,
    restricted_paths: &RestrictedPaths,
    manifest_id: ManifestId,
    manifest_type: ManifestType,
    source: ManifestRestrictionSource,
) -> Result<SourceRestrictionCheckResult> {
    let restriction_info = match source {
        ManifestRestrictionSource::Config => {
            restriction_info::get_manifest_restriction_info_from_config(
                restricted_paths,
                ctx,
                &manifest_id,
                &manifest_type,
            )
            .await
            .context("find config restrictions for manifest-side fetch")?
        }
        ManifestRestrictionSource::AclManifest => {
            restriction_info::get_manifest_restriction_info_from_acl_manifest(
                restricted_paths,
                ctx,
                &manifest_id,
                &manifest_type,
            )
            .await
            .context("find AclManifest restrictions for manifest-side fetch")?
        }
    };
    check_manifest_authorization(ctx, restricted_paths, restriction_info).await
}

async fn check_config_path_authorization(
    ctx: &CoreContext,
    restricted_paths: &RestrictedPaths,
    path: &NonRootMPath,
) -> Result<SourceRestrictionCheckResult> {
    let (restriction_info, restriction_acls) = restricted_paths
        .config()
        .path_acls
        .iter()
        .filter(|(prefix, _)| prefix.is_prefix_of(path))
        .map(|(restriction_root, acl)| {
            let repo_region_acl = acl.to_string();
            (
                PathRestrictionInfo {
                    restriction_root: restriction_root.clone(),
                    request_acl: repo_region_acl.clone(),
                    repo_region_acl,
                },
                acl.clone(),
            )
        })
        .unzip();

    check_path_authorization(ctx, restricted_paths, restriction_info, restriction_acls).await
}

async fn check_path_authorization(
    ctx: &CoreContext,
    restricted_paths: &RestrictedPaths,
    restriction_info: Vec<PathRestrictionInfo>,
    restriction_acls: Vec<MononokeIdentity>,
) -> Result<SourceRestrictionCheckResult> {
    if restriction_info.is_empty() {
        return Ok(SourceRestrictionCheckResult::unrestricted(Some(vec![])));
    }

    let restriction_paths = restriction_info
        .iter()
        .map(|info| info.restriction_root.clone())
        .collect::<Vec<_>>();
    let acl_refs = restriction_acls.iter().collect::<Vec<_>>();
    let authorization = check_authorization(
        ctx,
        restricted_paths.acl_provider(),
        &acl_refs,
        restricted_paths.config().tooling_allowlist_group.as_deref(),
        restricted_paths.config().rollout_allowlist_group.as_deref(),
    )
    .await?;

    Ok(SourceRestrictionCheckResult::new(
        authorization.has_authorization(),
        authorization.has_acl_access,
        restriction_acls,
        Some(restriction_paths),
        authorization.is_allowlisted_tooling,
        authorization.is_rollout_allowlisted,
    ))
}

fn parse_restriction_acls(
    restriction_info: &[PathRestrictionInfo],
) -> Result<Vec<MononokeIdentity>> {
    restriction_info
        .iter()
        .map(|info| {
            MononokeIdentity::from_str(&info.repo_region_acl).with_context(|| {
                format!("Failed to parse repo_region_acl {}", info.repo_region_acl)
            })
        })
        .collect()
}

async fn check_manifest_authorization(
    ctx: &CoreContext,
    restricted_paths: &RestrictedPaths,
    restriction_info: Vec<ManifestRestrictionInfo>,
) -> Result<SourceRestrictionCheckResult> {
    if restriction_info.is_empty() {
        return Ok(SourceRestrictionCheckResult::unrestricted(Some(vec![])));
    }

    let restriction_acls = restriction_info
        .iter()
        .map(|info| {
            MononokeIdentity::from_str(&info.repo_region_acl).with_context(|| {
                format!("Failed to parse repo_region_acl {}", info.repo_region_acl)
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let matched_restriction_paths = restriction_info
        .iter()
        .filter_map(|info| info.restriction_root.clone())
        .collect::<Vec<_>>();
    let matched_restriction_paths = if matched_restriction_paths.is_empty() {
        None
    } else {
        Some(matched_restriction_paths)
    };
    let acl_refs = restriction_acls.iter().collect::<Vec<_>>();
    let authorization = check_authorization(
        ctx,
        restricted_paths.acl_provider(),
        &acl_refs,
        restricted_paths.config().tooling_allowlist_group.as_deref(),
        restricted_paths.config().rollout_allowlist_group.as_deref(),
    )
    .await?;

    Ok(SourceRestrictionCheckResult::new(
        authorization.has_authorization(),
        authorization.has_acl_access,
        restriction_acls,
        matched_restriction_paths,
        authorization.is_allowlisted_tooling,
        authorization.is_rollout_allowlisted,
    ))
}
