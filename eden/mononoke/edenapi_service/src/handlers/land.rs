/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

use std::collections::HashMap;

use anyhow::Context;
use anyhow::Error;
use anyhow::format_err;
use async_trait::async_trait;
use bookmarks_movement::BookmarkKindRestrictions;
use bytes::Bytes;
use edenapi_types::HgId;
use edenapi_types::LandStackData;
use edenapi_types::LandStackRequest;
use edenapi_types::LandStackResponse;
use edenapi_types::ServerError;
use futures::StreamExt;
use futures::stream;
use hooks::PushAuthoredBy;
use mercurial_types::HgChangesetId;
use mercurial_types::HgNodeHash;
use mononoke_api::MononokeRepo;
use mononoke_api::Repo;
use mononoke_api_hg::HgRepoContext;
use repo_identity::RepoIdentityRef;

use super::HandlerResult;
use super::SaplingRemoteApiHandler;
use super::SaplingRemoteApiMethod;
use super::handler::SaplingRemoteApiContext;
use crate::errors::ErrorKind;

/// Rebase a stack of commits onto a bookmark, and update the bookmark to the top of the newly-rebased stack.
pub struct LandStackHandler;

#[async_trait]
impl SaplingRemoteApiHandler for LandStackHandler {
    type Request = LandStackRequest;
    type Response = LandStackResponse;

    const HTTP_METHOD: hyper::Method = hyper::Method::POST;
    const API_METHOD: SaplingRemoteApiMethod = SaplingRemoteApiMethod::LandStack;
    const ENDPOINT: &'static str = "/land";

    async fn handler(
        ectx: SaplingRemoteApiContext<Self::PathExtractor, Self::QueryStringExtractor, Repo>,
        request: Self::Request,
    ) -> HandlerResult<'async_trait, Self::Response> {
        Ok(stream::once(land_stack_response(
            ectx.repo(),
            request.bookmark,
            request.head,
            request.base,
            request
                .pushvars
                .into_iter()
                .map(|p| (p.key, p.value.into()))
                .collect(),
        ))
        .boxed())
    }

    fn extract_in_band_error(response: &Self::Response) -> Option<anyhow::Error> {
        response
            .data
            .as_ref()
            .err()
            .map(|err| format_err!("{:?}", err))
    }
}

async fn land_stack_response<R: MononokeRepo>(
    repo: HgRepoContext<R>,
    bookmark: String,
    head_hgid: HgId,
    base_hgid: HgId,
    pushvars: HashMap<String, Bytes>,
) -> Result<LandStackResponse, Error> {
    Ok(LandStackResponse {
        data: land_stack(repo, bookmark, head_hgid, base_hgid, pushvars)
            .await
            .map_err(|e| ServerError::generic(format!("{:?}", e))),
    })
}

async fn land_stack<R: MononokeRepo>(
    repo: HgRepoContext<R>,
    bookmark: String,
    head_hgid: HgId,
    base_hgid: HgId,
    pushvars: HashMap<String, Bytes>,
) -> Result<LandStackData, Error> {
    let repo = repo.repo_ctx();

    let head = HgChangesetId::new(HgNodeHash::from(head_hgid));
    let head = repo
        .changeset(head)
        .await
        .context("failed to resolve head")?
        .ok_or(ErrorKind::HgIdNotFound(head_hgid))?
        .id();

    let base = HgChangesetId::new(HgNodeHash::from(base_hgid));
    let base = repo
        .changeset(base)
        .await
        .context("failed to resolve base")?
        .ok_or(ErrorKind::HgIdNotFound(base_hgid))?
        .id();

    let force_local_pushrebase = justknobs::eval(
        "scm/mononoke:edenapi_force_local_pushrebase",
        None,
        Some(repo.repo().repo_identity().name()),
    )
    .unwrap_or(false);

    let pushrebase_outcome = repo
        .land_stack(
            bookmark,
            head,
            base,
            if pushvars.is_empty() {
                None
            } else {
                Some(&pushvars)
            },
            BookmarkKindRestrictions::AnyKind,
            PushAuthoredBy::User,
            force_local_pushrebase,
        )
        .await?;

    let new_head = pushrebase_outcome.head;
    let (old_ids, new_ids): (Vec<_>, Vec<_>) = pushrebase_outcome
        .rebased_changesets
        .into_iter()
        .map(|pair| (pair.id_old, pair.id_new))
        .unzip();

    let all_ids = std::iter::once(new_head)
        .chain(old_ids.iter().copied())
        .chain(new_ids.iter().copied())
        .collect();
    let all_hgids: HashMap<_, _> = repo
        .many_changeset_hg_ids(all_ids)
        .await?
        .into_iter()
        .collect();

    let new_head_hgid = all_hgids
        .get(&new_head)
        .ok_or(ErrorKind::BonsaiChangesetToHgIdError(new_head))
        .context("failed to fetch hgid for new head")?
        .into_nodehash()
        .into();

    let old_hgids: Result<Vec<_>, _> = old_ids
        .iter()
        .map(|id| {
            all_hgids
                .get(id)
                .ok_or(ErrorKind::BonsaiChangesetToHgIdError(*id))
                .context("failed to fetch hgids for old ids")
                .map(|id| id.into_nodehash().into())
        })
        .collect();

    let new_hgids: Result<Vec<_>, _> = new_ids
        .iter()
        .map(|id| {
            all_hgids
                .get(id)
                .ok_or(ErrorKind::BonsaiChangesetToHgIdError(*id))
                .context("failed to fetch hgids for new ids")
                .map(|id| id.into_nodehash().into())
        })
        .collect();

    let old_to_new_hgids = old_hgids?.into_iter().zip(new_hgids?.into_iter()).collect();

    Ok(LandStackData {
        new_head: new_head_hgid,
        old_to_new_hgids,
    })
}
