/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

//! Implement traits from other crates.

use cas_client::CasClient;
use futures::stream;
use futures::stream::BoxStream;
use futures::StreamExt;
use hgstore::split_hg_file_metadata;
use hgstore::strip_hg_file_metadata;
use storemodel::types;
use storemodel::BoxIterator;
use storemodel::FileStore;
use storemodel::InsertOpts;
use storemodel::KeyStore;
use storemodel::Kind;
use storemodel::ReadRootTreeIds;
use storemodel::SerializationFormat;
use storemodel::TreeStore;
use types::CasDigest;
use types::CasDigestType;
use types::HgId;
use types::Key;
use types::RepoPath;

use crate::EagerRepoStore;

// storemodel traits

impl KeyStore for EagerRepoStore {
    fn get_local_content(
        &self,
        _path: &RepoPath,
        id: HgId,
    ) -> anyhow::Result<Option<minibytes::Bytes>> {
        match self.get_content(id)? {
            Some(data) => {
                let data = match self.format {
                    SerializationFormat::Hg => split_hg_file_metadata(&data).0,
                    SerializationFormat::Git => data,
                };
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    fn insert_data(
        &self,
        mut opts: InsertOpts,
        _path: &RepoPath,
        data: &[u8],
    ) -> anyhow::Result<HgId> {
        let mut sha1_data;
        match self.format {
            SerializationFormat::Hg => {
                sha1_data = Vec::with_capacity(data.len() + HgId::len() * 2);
                // Calculate the "hg" text: sorted([p1, p2]) + data
                opts.parents.sort_unstable();
                let mut iter = opts.parents.iter().rev();
                let p2 = iter.next().copied().unwrap_or_else(|| *HgId::null_id());
                let p1 = iter.next().copied().unwrap_or_else(|| *HgId::null_id());
                sha1_data.extend_from_slice(p1.as_ref());
                sha1_data.extend_from_slice(p2.as_ref());
                sha1_data.extend_from_slice(data);
                drop(iter);
            }
            SerializationFormat::Git => {
                let size_str = data.len().to_string();
                let type_str = match opts.kind {
                    Kind::File => "blob",
                    Kind::Tree => "tree",
                };
                sha1_data = Vec::with_capacity(data.len() + type_str.len() + size_str.len() + 2);
                sha1_data.extend_from_slice(type_str.as_bytes());
                sha1_data.push(b' ');
                sha1_data.extend_from_slice(size_str.as_bytes());
                sha1_data.push(0);
                sha1_data.extend_from_slice(data);
            }
        };

        if let Some(id) = opts.forced_id {
            let id = *id;
            self.add_arbitrary_blob(id, &sha1_data)?;
            Ok(id)
        } else {
            let id = self.add_sha1_blob(&sha1_data, &opts.parents)?;
            Ok(id)
        }
    }

    fn flush(&self) -> anyhow::Result<()> {
        let mut inner = self.inner.write();
        inner.flush()?;
        Ok(())
    }

    fn refresh(&self) -> anyhow::Result<()> {
        let mut inner = self.inner.write();
        inner.flush()?;
        Ok(())
    }

    fn format(&self) -> SerializationFormat {
        self.format
    }

    fn maybe_as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
}

impl FileStore for EagerRepoStore {
    fn get_rename_iter(
        &self,
        keys: Vec<Key>,
    ) -> anyhow::Result<BoxIterator<anyhow::Result<(Key, Key)>>> {
        match self.format {
            SerializationFormat::Hg => {
                let iter = keys.into_iter().filter_map(|k| {
                    let id = k.hgid;
                    match self.get_content(id) {
                        Err(e) => Some(Err(e.into())),
                        Ok(Some(data)) => match strip_hg_file_metadata(&data) {
                            Err(e) => Some(Err(e)),
                            Ok((_, Some(copy_from))) => Some(Ok((k, copy_from))),
                            Ok((_, None)) => None,
                        },
                        Ok(None) => Some(Err(anyhow::format_err!("no such file: {:?}", &k))),
                    }
                });
                Ok(Box::new(iter))
            }
            SerializationFormat::Git => Ok(Box::new(std::iter::empty())),
        }
    }

    fn get_hg_parents(&self, _path: &RepoPath, id: HgId) -> anyhow::Result<Vec<HgId>> {
        match self.format {
            SerializationFormat::Hg => {
                let mut parents = Vec::new();
                if let Some(blob) = self.get_sha1_blob(id)? {
                    for start in [HgId::len(), 0] {
                        let end = start + HgId::len();
                        if let Some(slice) = blob.get(start..end) {
                            if let Ok(id) = HgId::from_slice(slice) {
                                if !id.is_null() {
                                    parents.push(id);
                                }
                            }
                        }
                    }
                }
                Ok(parents)
            }
            // For Git, just return a dummy empty "parents".
            SerializationFormat::Git => Ok(Vec::new()),
        }
    }
}

impl TreeStore for EagerRepoStore {}

#[async_trait::async_trait]
impl ReadRootTreeIds for EagerRepoStore {
    async fn read_root_tree_ids(&self, commits: Vec<HgId>) -> anyhow::Result<Vec<(HgId, HgId)>> {
        let mut res = Vec::new();
        for commit in &commits {
            let content = self.get_content(*commit)?;
            if let Some(data) = content {
                let tree_id = HgId::from_hex(&data[0..HgId::hex_len()])?;
                res.push((commit.clone(), tree_id));
            }
        }
        Ok(res)
    }
}

#[async_trait::async_trait]
impl CasClient for EagerRepoStore {
    async fn fetch<'a>(
        &'a self,
        digests: &'a [CasDigest],
        log_name: CasDigestType,
    ) -> BoxStream<'a, anyhow::Result<Vec<(CasDigest, anyhow::Result<Option<Vec<u8>>>)>>> {
        stream::once(async move {
            tracing::debug!(target: "cas", "EagerRepoStore fetching {} {}(s)", digests.len(), log_name);

            Ok(digests
                .iter()
                .map(|digest| {
                    (
                        *digest,
                        self.get_cas_blob(*digest)
                            .map_err(Into::into)
                            .map(|data| data.map(|data| data.into_vec())),
                    )
                })
                .collect())
        }).boxed()
    }
}
