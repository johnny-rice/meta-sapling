/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use manifest::testutil::*;
use manifest::Manifest;
use minibytes::Bytes;
use parking_lot::Mutex;
use parking_lot::RwLock;
use sha1::Digest;
use sha1::Sha1;
use storemodel::InsertOpts;
use storemodel::KeyStore;
use storemodel::SerializationFormat;
use types::testutil::*;
use types::HgId;
use types::Key;
use types::RepoPath;
use types::RepoPathBuf;

use crate::FileMetadata;
use crate::TreeManifest;
use crate::TreeStore;

pub fn make_tree_manifest<'a>(
    store: Arc<TestStore>,
    paths: impl IntoIterator<Item = &'a (&'a str, &'a str)>,
) -> TreeManifest {
    let mut tree = TreeManifest::ephemeral(store);
    for (path, filenode) in paths {
        tree.insert(repo_path_buf(path), make_meta(filenode))
            .unwrap();
    }
    tree
}

pub fn make_tree_manifest_from_meta(
    store: Arc<TestStore>,
    paths: impl IntoIterator<Item = (RepoPathBuf, FileMetadata)>,
) -> TreeManifest {
    let mut tree = TreeManifest::ephemeral(store);
    for (path, meta) in paths {
        tree.insert(path, meta).unwrap();
    }
    tree
}

/// An in memory `Store` implementation backed by HashMaps. Primarily intended for tests.
#[derive(Default)]
pub struct TestStore {
    entries: RwLock<HashMap<RepoPathBuf, HashMap<HgId, Bytes>>>,
    pub prefetched: Mutex<Vec<Vec<Key>>>,
    format: SerializationFormat,
    key_fetch_count: AtomicU64,
    insert_count: AtomicU64,
}

impl TestStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_format(mut self, format: SerializationFormat) -> Self {
        self.format = format;
        self
    }

    #[allow(unused)]
    pub fn fetches(&self) -> Vec<Vec<Key>> {
        self.prefetched.lock().clone()
    }

    pub fn key_fetch_count(&self) -> u64 {
        self.key_fetch_count.load(Ordering::Relaxed)
    }

    pub fn insert_count(&self) -> u64 {
        self.insert_count.load(Ordering::Relaxed)
    }
}

fn compute_sha1(content: &[u8]) -> HgId {
    let mut hasher = Sha1::new();
    hasher.update(content);
    let buf: [u8; HgId::len()] = hasher.finalize().into();
    (&buf).into()
}

impl KeyStore for TestStore {
    fn get_local_content(&self, path: &RepoPath, hgid: HgId) -> anyhow::Result<Option<Bytes>> {
        self.key_fetch_count.fetch_add(1, Ordering::Relaxed);
        let underlying = self.entries.read();
        let result = underlying
            .get(path)
            .and_then(|hgid_hash| hgid_hash.get(&hgid))
            .cloned();
        Ok(result)
    }

    fn insert_data(&self, opts: InsertOpts, path: &RepoPath, data: &[u8]) -> anyhow::Result<HgId> {
        self.insert_count.fetch_add(1, Ordering::Relaxed);
        let mut underlying = self.entries.write();
        let hgid = match opts.forced_id {
            Some(id) => *id,
            None => compute_sha1(data),
        };
        underlying
            .entry(path.to_owned())
            .or_insert(HashMap::new())
            .insert(hgid, Bytes::copy_from_slice(data));
        Ok(hgid)
    }

    fn prefetch(&self, keys: Vec<Key>) -> Result<()> {
        self.key_fetch_count
            .fetch_add(keys.len() as u64, Ordering::Relaxed);
        self.prefetched.lock().push(keys);
        Ok(())
    }

    fn format(&self) -> SerializationFormat {
        self.format
    }
}

impl TreeStore for TestStore {}
