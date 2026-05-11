/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#[cfg(fbcode_build)]
use anyhow::Error;
#[cfg(fbcode_build)]
use cats_constants::X_AUTH_CATS_HEADER;
use fbinit::FacebookInit;
use http::HeaderMap;
use metaconfig_types::Identity;
use permission_checker::MononokeIdentitySet;
#[cfg(fbcode_build)]
use tracing::debug;
#[cfg(fbcode_build)]
use tracing::warn;

#[cfg(not(fbcode_build))]
pub fn try_get_cats_idents(
    _fb: FacebookInit,
    _headers: &HeaderMap,
    _verifier_identity: &Identity,
) -> Option<MononokeIdentitySet> {
    None
}

/// Extract identities from CAT tokens in the request headers.
///
/// Returns `None` when no CAT header is present or when the header itself is
/// malformed (e.g. invalid base64). When the header parses, returns
/// `Some(set)` containing the identities of every token that successfully
/// verified — invalid tokens are silently dropped.
///
/// When the `scm/mononoke:cats_use_authenticated_identity_struct` JustKnob is
/// set, the resulting identities are `MononokeIdentity::Authenticated` carrying
/// the full `AuthenticatedIdentity` thrift struct (including attributes
/// extracted from the verified token's `metaIdUri`, matching srserver's
/// `authenticated_identities_cats_struct` path). Otherwise the legacy path is
/// used, producing `MononokeIdentity::TypeData` from the token's signer
/// identity.
#[cfg(fbcode_build)]
pub fn try_get_cats_idents(
    fb: FacebookInit,
    headers: &HeaderMap,
    verifier_identity: &Identity,
) -> Option<MononokeIdentitySet> {
    match parse_cat_token_list(headers) {
        Ok(None) => None,
        Ok(Some(cat_list)) => Some(verify_cat_tokens(fb, cat_list, verifier_identity)),
        Err(e) => {
            warn!(
                "Error extracting CATs identities: {}. Ignoring CAT token.",
                e
            );
            None
        }
    }
}

#[cfg(fbcode_build)]
fn parse_cat_token_list(
    headers: &HeaderMap,
) -> Result<Option<cryptocat::CryptoAuthTokenList>, Error> {
    let cats = match headers.get(X_AUTH_CATS_HEADER) {
        Some(cats) => cats,
        None => {
            debug!("CAT extraction: no {} header present", X_AUTH_CATS_HEADER);
            return Ok(None);
        }
    };
    let s_cats = cats.to_str()?;
    let cat_list = cryptocat::deserialize_crypto_auth_tokens(s_cats)?;
    debug!(
        "CAT extraction: received {} token(s) in {} header",
        cat_list.tokens.len(),
        X_AUTH_CATS_HEADER,
    );
    Ok(Some(cat_list))
}

#[cfg(fbcode_build)]
fn verify_cat_tokens(
    fb: FacebookInit,
    cat_list: cryptocat::CryptoAuthTokenList,
    verifier_identity: &Identity,
) -> MononokeIdentitySet {
    let svc_scm_ident = cryptocat::Identity {
        id_type: verifier_identity.id_type.clone(),
        id_data: verifier_identity.id_data.clone(),
        ..Default::default()
    };

    if justknobs::eval(
        "scm/mononoke:cats_use_authenticated_identity_struct",
        None,
        None,
    )
    .expect("This JK doesn't exist?")
    {
        verify_cat_tokens_authenticated(fb, cat_list, &svc_scm_ident)
    } else {
        verify_cat_tokens_legacy(fb, cat_list, &svc_scm_ident, verifier_identity)
    }
}

#[cfg(fbcode_build)]
fn verify_cat_tokens_authenticated(
    fb: FacebookInit,
    cat_list: cryptocat::CryptoAuthTokenList,
    svc_scm_ident: &cryptocat::Identity,
) -> MononokeIdentitySet {
    use login_objects_thrift::EnvironmentType;

    debug!(
        "CAT extraction: bulk-verifying {} token(s) via authenticated_identity path",
        cat_list.tokens.len(),
    );
    match cryptocat::verify_and_extract_authenticated_identities(
        fb,
        cat_list,
        svc_scm_ident,
        None,
        vec![EnvironmentType::PROD, EnvironmentType::CORP],
    ) {
        Ok(idents) => idents
            .into_iter()
            .map(|auth_id| {
                debug!(
                    "CAT extraction: extracted identity {}:{}",
                    auth_id.identity.id_type, auth_id.identity.id_data,
                );
                permission_checker::MononokeIdentity::Authenticated(auth_id)
            })
            .collect(),
        Err(e) => {
            warn!(
                "CAT extraction: bulk verify failed: {}. Returning empty set.",
                e
            );
            MononokeIdentitySet::new()
        }
    }
}

#[cfg(fbcode_build)]
fn verify_cat_tokens_legacy(
    fb: FacebookInit,
    cat_list: cryptocat::CryptoAuthTokenList,
    svc_scm_ident: &cryptocat::Identity,
    verifier_identity: &Identity,
) -> MononokeIdentitySet {
    cat_list
        .tokens
        .into_iter()
        .filter_map(|token| {
            extract_identity_from_token(fb, svc_scm_ident, verifier_identity, token)
        })
        .collect()
}

#[cfg(fbcode_build)]
fn extract_identity_from_token(
    fb: FacebookInit,
    svc_scm_ident: &cryptocat::Identity,
    verifier_identity: &Identity,
    token: cryptocat::CryptoAuthToken,
) -> Option<permission_checker::MononokeIdentity> {
    let tdata = match cryptocat::deserialize_crypto_auth_token_data(
        &token.serializedCryptoAuthTokenData[..],
    ) {
        Ok(tdata) => tdata,
        Err(e) => {
            warn!("CAT token skipped: failed to deserialize token data: {}", e);
            return None;
        }
    };

    if tdata.verifierIdentity.id_type != verifier_identity.id_type
        || tdata.verifierIdentity.id_data != verifier_identity.id_data
    {
        debug!(
            "CAT token skipped: verifier identity mismatch (token has {}:{}, expected {}:{})",
            tdata.verifierIdentity.id_type,
            tdata.verifierIdentity.id_data,
            verifier_identity.id_type,
            verifier_identity.id_data,
        );
        return None;
    }

    match cryptocat::verify_crypto_auth_token(fb, token, svc_scm_ident, None) {
        Ok(res) if res.code == cryptocat::CATVerificationCode::SUCCESS => {}
        Ok(res) => {
            warn!(
                "CAT token skipped: verification not successful. status code: {:?}",
                res.code,
            );
            return None;
        }
        Err(e) => {
            warn!("CAT token skipped: verification error: {}", e);
            return None;
        }
    }

    debug!(
        "CAT extraction: extracted identity {}:{}",
        tdata.signerIdentity.id_type, tdata.signerIdentity.id_data,
    );
    Some(permission_checker::MononokeIdentity::new(
        tdata.signerIdentity.id_type,
        tdata.signerIdentity.id_data,
    ))
}
