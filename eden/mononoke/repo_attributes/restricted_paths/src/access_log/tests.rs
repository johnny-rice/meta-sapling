/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use context::CoreContext;
use fbinit::FacebookInit;
use metaconfig_types::AclManifestMode;
use mononoke_macros::mononoke;
use mononoke_types::NonRootMPath;
use mononoke_types::RepositoryId;
use permission_checker::MononokeIdentity;
use scuba_ext::MononokeScubaSampleBuilder;
use serde_json::Value;
use serde_json::json;

use super::RestrictedPathAccessData;
use super::SourceRestrictionCheckResult;
use super::SourceRestrictionResult;
use super::log_source_results_to_scuba;
use crate::ManifestId;
use crate::ManifestType;

struct ShadowComparisonFieldFixture {
    ctx: CoreContext,
    repo_id: RepositoryId,
    acl_manifest_mode: AclManifestMode,
    config_result: Option<SourceRestrictionResult>,
    acl_manifest_result: Option<SourceRestrictionResult>,
    access_data: RestrictedPathAccessData,
    scuba: MononokeScubaSampleBuilder,
    log_path: PathBuf,
}

impl ShadowComparisonFieldFixture {
    fn new(
        fb: FacebookInit,
        config_result: Option<SourceRestrictionResult>,
        acl_manifest_result: Option<SourceRestrictionResult>,
        access_data: RestrictedPathAccessData,
    ) -> Result<Self> {
        let temp_log_file = tempfile::NamedTempFile::new()?;
        let log_path = temp_log_file.into_temp_path().keep()?;
        let scuba = MononokeScubaSampleBuilder::with_discard().with_log_file(&log_path)?;

        Ok(Self {
            ctx: CoreContext::test_mock(fb),
            repo_id: RepositoryId::new(1),
            acl_manifest_mode: AclManifestMode::Shadow,
            config_result,
            acl_manifest_result,
            access_data,
            scuba,
            log_path,
        })
    }

    fn log_with(
        self,
        log_results: impl FnOnce(
            &CoreContext,
            RepositoryId,
            Option<&SourceRestrictionResult>,
            Option<&SourceRestrictionResult>,
            AclManifestMode,
            RestrictedPathAccessData,
            MononokeScubaSampleBuilder,
        ) -> Result<()>,
    ) -> Result<Vec<serde_json::Map<String, Value>>> {
        let Self {
            ctx,
            repo_id,
            acl_manifest_mode,
            config_result,
            acl_manifest_result,
            access_data,
            scuba,
            log_path,
        } = self;

        log_results(
            &ctx,
            repo_id,
            config_result.as_ref(),
            acl_manifest_result.as_ref(),
            acl_manifest_mode,
            access_data,
            scuba,
        )?;
        read_logged_samples(&log_path)
    }
}

// What it tests: Shadow logging can surface compact comparison fields for
// config and AclManifest results.
// Expected: source attribution and mismatch summary fields are emitted.
#[mononoke::fbinit_test]
async fn test_shadow_mismatch_summary_fields_are_logged(fb: FacebookInit) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(restricted_result(
            false,
            false,
            "config_acl",
            Some("config/restricted"),
        )?),
        Some(restricted_result(
            true,
            true,
            "acl_manifest_acl",
            Some("acl_manifest/restricted"),
        )?),
        full_path_access_data()?,
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples.len(), 1);
    let sample = &samples[0];
    assert_eq!(
        sample_field(sample, "acl_manifest_mode"),
        Some("shadow".to_string())
    );
    assert_eq!(
        sample_field(sample, "shadow_mismatch"),
        Some("true".to_string())
    );
    assert_eq!(
        sample_array(sample, "considered_restricted_by"),
        vec!["manifest_db".to_string(), "acl_manifest".to_string()]
    );

    let detail = sample_json_field(sample, "shadow_mismatch_detail")?
        .ok_or_else(|| anyhow!("missing shadow_mismatch_detail"))?;
    assert_eq!(
        detail["differences"],
        json!(["has_authorization", "restriction_acls", "restriction_paths"])
    );
    assert_eq!(detail["config"]["restricted"], json!(true));
    assert_eq!(detail["config"]["has_authorization"], json!(false));
    assert_eq!(
        detail["config"]["restriction_acls"],
        json!(["REPO_REGION:config_acl"])
    );
    assert_eq!(
        detail["config"]["restriction_paths"],
        json!(["config/restricted"])
    );
    assert_eq!(detail["acl_manifest"]["restricted"], json!(true));
    assert_eq!(detail["acl_manifest"]["has_authorization"], json!(true));
    assert_eq!(
        detail["acl_manifest"]["restriction_acls"],
        json!(["REPO_REGION:acl_manifest_acl"])
    );
    assert_eq!(
        detail["acl_manifest"]["restriction_paths"],
        json!(["acl_manifest/restricted"])
    );
    Ok(())
}

// What it tests: Shadow logging records the parity case where both sources
// report the same restricted result.
// Expected: a row is emitted without mismatch detail when both sources agree.
#[mononoke::fbinit_test]
async fn test_shadow_matching_restricted_sources_log_row_without_mismatch(
    fb: FacebookInit,
) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(restricted_result(
            false,
            false,
            "shared_acl",
            Some("shared/restricted"),
        )?),
        Some(restricted_result(
            false,
            false,
            "shared_acl",
            Some("shared/restricted"),
        )?),
        full_path_access_data()?,
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples.len(), 1);
    let sample = &samples[0];
    assert_eq!(
        sample_array(sample, "considered_restricted_by"),
        vec!["manifest_db".to_string(), "acl_manifest".to_string()]
    );
    assert_eq!(
        sample_array(sample, "restricted_paths"),
        vec!["shared/restricted".to_string()]
    );
    assert_eq!(
        sample_array(sample, "acls"),
        vec!["REPO_REGION:shared_acl".to_string()]
    );
    assert_eq!(
        sample_field(sample, "shadow_mismatch"),
        Some("false".to_string())
    );
    assert_eq!(sample_field(sample, "shadow_mismatch_detail"), None);
    Ok(())
}

// What it tests: restriction-root-only differences stay diagnostic-only.
// Expected: the broad mismatch detail is populated, but the queryable mismatch
// boolean remains false.
#[mononoke::fbinit_test]
async fn test_shadow_root_only_differences_do_not_set_shadow_mismatch(
    fb: FacebookInit,
) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(restricted_result(
            false,
            false,
            "shared_acl",
            Some("config/restricted"),
        )?),
        Some(restricted_result(false, false, "shared_acl", None)?),
        manifest_access_data(ManifestType::HgAugmented),
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples.len(), 1);
    let sample = &samples[0];
    assert_eq!(
        sample_field(sample, "shadow_mismatch"),
        Some("false".to_string())
    );
    let detail = sample_json_field(sample, "shadow_mismatch_detail")?
        .ok_or_else(|| anyhow!("missing shadow_mismatch_detail"))?;
    assert_eq!(detail["differences"], json!(["restriction_paths"]));
    Ok(())
}

// What it tests: Shadow aggregate fields stay config-authoritative while
// AclManifest contributes comparison-only telemetry.
// Expected: top-level aggregate fields are derived from config, while
// AclManifest disagreement is recorded in the mismatch summary.
#[mononoke::fbinit_test]
async fn test_shadow_aggregate_fields_stay_config_authoritative(fb: FacebookInit) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(restricted_result(
            false,
            false,
            "config_acl",
            Some("config/restricted"),
        )?),
        Some(unrestricted_result(Some(vec![]))),
        manifest_access_data(ManifestType::HgAugmented),
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples.len(), 1);
    let sample = &samples[0];
    assert_eq!(
        sample_field(sample, "has_authorization"),
        Some("false".to_string())
    );
    assert_eq!(
        sample_field(sample, "has_acl_access"),
        Some("false".to_string())
    );
    assert_eq!(
        sample_array(sample, "restricted_paths"),
        vec!["config/restricted".to_string()]
    );
    assert_eq!(
        sample_array(sample, "acls"),
        vec!["REPO_REGION:config_acl".to_string()]
    );
    assert_eq!(
        sample_array(sample, "considered_restricted_by"),
        vec!["manifest_db".to_string()]
    );
    assert_eq!(
        sample_field(sample, "shadow_mismatch"),
        Some("true".to_string())
    );
    let detail = sample_json_field(sample, "shadow_mismatch_detail")?
        .ok_or_else(|| anyhow!("missing shadow_mismatch_detail"))?;
    assert_eq!(
        detail["differences"],
        json!([
            "restricted",
            "has_authorization",
            "restriction_acls",
            "restriction_paths"
        ])
    );
    assert_eq!(detail["config"]["restricted"], json!(true));
    assert_eq!(detail["acl_manifest"]["restricted"], json!(false));
    Ok(())
}

// What it tests: Shadow comparison errors are logged without changing the
// config-authoritative aggregate result.
// Expected: the AclManifest error and mismatch summary fields are populated
// while top-level authorization still comes from the config source.
#[mononoke::fbinit_test]
async fn test_shadow_comparison_errors_are_logged(fb: FacebookInit) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(unrestricted_result(Some(vec![]))),
        Some(error_result("acl manifest lookup failed")),
        full_path_access_data()?,
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples.len(), 1);
    let sample = &samples[0];
    assert_eq!(
        sample_field(sample, "has_authorization"),
        Some("true".to_string())
    );
    assert_eq!(sample_field(sample, "config_error"), None);
    assert!(
        sample_field(sample, "acl_manifest_error")
            .is_some_and(|value| value.contains("acl manifest lookup failed"))
    );
    assert_eq!(
        sample_array(sample, "considered_restricted_by"),
        Vec::<String>::new()
    );
    assert_eq!(
        sample_field(sample, "shadow_mismatch"),
        Some("true".to_string())
    );
    let detail = sample_json_field(sample, "shadow_mismatch_detail")?
        .ok_or_else(|| anyhow!("missing shadow_mismatch_detail"))?;
    assert_eq!(detail["differences"], json!(["acl_manifest_error"]));
    assert_eq!(
        detail["acl_manifest"]["error"],
        json!("acl manifest lookup failed")
    );
    Ok(())
}

// What it tests: Shadow emits error-only rows when both sources fail.
// Expected: both source-specific error fields and mismatch summary are present
// without top-level aggregate authorization fields.
#[mononoke::fbinit_test]
async fn test_shadow_error_only_rows_are_logged(fb: FacebookInit) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(error_result("config lookup failed")),
        Some(error_result("acl manifest lookup failed")),
        full_path_access_data()?,
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples.len(), 1);
    let sample = &samples[0];
    assert_eq!(sample_field(sample, "has_authorization"), None);
    assert!(
        sample_field(sample, "config_error")
            .is_some_and(|value| value.contains("config lookup failed"))
    );
    assert!(
        sample_field(sample, "acl_manifest_error")
            .is_some_and(|value| value.contains("acl manifest lookup failed"))
    );
    assert_eq!(
        sample_field(sample, "shadow_mismatch"),
        Some("false".to_string())
    );
    let detail = sample_json_field(sample, "shadow_mismatch_detail")?
        .ok_or_else(|| anyhow!("missing shadow_mismatch_detail"))?;
    assert_eq!(
        detail["differences"],
        json!(["config_error", "acl_manifest_error"])
    );
    Ok(())
}

// What it tests: a skipped comparison source stays distinct from an
// unrestricted source.
// Expected: skipped AclManifest comparison does not produce an error, mismatch
// detail, or AclManifest source attribution.
#[mononoke::fbinit_test]
async fn test_shadow_skipped_comparison_source_is_not_logged(fb: FacebookInit) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(restricted_result(
            false,
            false,
            "config_acl",
            Some("config/restricted"),
        )?),
        None,
        manifest_access_data(ManifestType::Hg),
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples.len(), 1);
    let sample = &samples[0];
    assert_eq!(sample_field(sample, "acl_manifest_error"), None);
    assert_eq!(
        sample_field(sample, "shadow_mismatch"),
        Some("false".to_string())
    );
    assert_eq!(sample_field(sample, "shadow_mismatch_detail"), None);
    assert_eq!(
        sample_array(sample, "considered_restricted_by"),
        vec!["manifest_db".to_string()]
    );
    Ok(())
}

// What it tests: successful unrestricted source results do not emit a row.
// Expected: no Scuba row is written when both sources are unrestricted.
#[mononoke::fbinit_test]
async fn test_shadow_unrestricted_sources_do_not_log_rows(fb: FacebookInit) -> Result<()> {
    let samples = ShadowComparisonFieldFixture::new(
        fb,
        Some(unrestricted_result(Some(vec![]))),
        Some(unrestricted_result(Some(vec![]))),
        full_path_access_data()?,
    )?
    .log_with(log_source_results_to_scuba)?;

    assert_eq!(samples, Vec::<serde_json::Map<String, Value>>::new());
    Ok(())
}

fn restricted_result(
    has_authorization: bool,
    has_acl_access: bool,
    acl_name: &str,
    restriction_path: Option<&str>,
) -> Result<SourceRestrictionResult> {
    Ok(Ok(Arc::new(SourceRestrictionCheckResult::new(
        has_authorization,
        has_acl_access,
        vec![MononokeIdentity::new("REPO_REGION", acl_name)],
        restriction_path
            .map(|path| NonRootMPath::new(path).map(|path| vec![path]))
            .transpose()?,
        false,
        false,
    ))))
}

fn unrestricted_result(restriction_paths: Option<Vec<NonRootMPath>>) -> SourceRestrictionResult {
    Ok(Arc::new(SourceRestrictionCheckResult::unrestricted(
        restriction_paths,
    )))
}

fn error_result(message: &str) -> SourceRestrictionResult {
    Err(Arc::new(anyhow!("{message}")))
}

fn full_path_access_data() -> Result<RestrictedPathAccessData> {
    Ok(RestrictedPathAccessData::FullPath {
        full_path: NonRootMPath::new("requested/path")?,
    })
}

fn manifest_access_data(manifest_type: ManifestType) -> RestrictedPathAccessData {
    RestrictedPathAccessData::Manifest(
        ManifestId::from("1111111111111111111111111111111111111111"),
        manifest_type,
    )
}

fn read_logged_samples(log_path: &std::path::Path) -> Result<Vec<serde_json::Map<String, Value>>> {
    let contents = std::fs::read_to_string(log_path)
        .with_context(|| format!("failed to read scuba log {}", log_path.display()))?;
    contents
        .lines()
        .map(|line| {
            let json: Value = serde_json::from_str(line)
                .with_context(|| format!("failed to parse scuba row: {line}"))?;
            flatten_scuba_sample(&json)
        })
        .collect()
}

fn flatten_scuba_sample(json: &Value) -> Result<serde_json::Map<String, Value>> {
    let top_level = json
        .as_object()
        .ok_or_else(|| anyhow!("top-level scuba row should be a JSON object"))?;
    Ok(top_level
        .values()
        .filter_map(Value::as_object)
        .flat_map(|category| category.iter())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn sample_field(sample: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    match sample.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        Some(other) => Some(other.to_string()),
        None => None,
    }
}

fn sample_json_field(sample: &serde_json::Map<String, Value>, key: &str) -> Result<Option<Value>> {
    sample_field(sample, key)
        .map(|value| {
            serde_json::from_str(&value)
                .with_context(|| format!("failed to parse {key} as JSON: {value}"))
        })
        .transpose()
}

fn sample_array(sample: &serde_json::Map<String, Value>, key: &str) -> Vec<String> {
    match sample.get(key).and_then(Value::as_array) {
        Some(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect(),
        None => Vec::new(),
    }
}
