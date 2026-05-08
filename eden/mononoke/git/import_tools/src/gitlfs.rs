/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

use core::future::Future;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Error;
use anyhow::format_err;
use bytes::Bytes;
use clientinfo::CLIENT_INFO_HEADER;
use clientinfo::ClientInfo;
use context::CoreContext;
use filestore::StoreRequest;
use futures::Stream;
use futures::StreamExt;
use futures::TryStreamExt;
use futures::stream;
use git_types::git_lfs::LfsPointerData;
use git_types::git_lfs::parse_lfs_pointer;
use gix_hash::ObjectId;
use http::HeaderValue;
use http::Request;
use http::StatusCode;
use http::Uri;
use http_body_util::BodyExt as _;
use http_body_util::Full;
use hyper_openssl::client::legacy::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use mononoke_macros::mononoke;
use mononoke_types::hash;
use openssl::ssl::SslConnector;
use openssl::ssl::SslFiletype;
use openssl::ssl::SslMethod;
use repourl::encode_repo_name;
use tls::TLSArgs;
use tokio::sync::Semaphore;
use tokio::time::Duration;
use tokio::time::sleep;
use tracing::error;
use tracing::warn;

/// URL pattern used by the upstream LFS server to serve a single object keyed by SHA256.
/// `LegacyDewey` matches Dewey's bare-suffix scheme; `MononokeGitLfs` matches the
/// Mononoke LFS server's `/{repo}/download_sha256/{oid}` route.
#[derive(Clone, Debug, Default)]
pub enum LfsServerUrlFormat {
    /// `GET {server}/{sha256}`
    #[default]
    LegacyDewey,
    /// `GET {server}/{repo_name}/download_sha256/{sha256}`
    MononokeGitLfs { repo_name: String },
}

impl LfsServerUrlFormat {
    fn build_object_url(&self, lfs_server: &str, sha256: &hash::Sha256) -> Result<Uri, Error> {
        let base = lfs_server.trim_end_matches('/');
        let url = match self {
            Self::LegacyDewey => format!("{base}/{sha256}"),
            Self::MononokeGitLfs { repo_name } => {
                format!(
                    "{base}/{}/download_sha256/{sha256}",
                    encode_repo_name(repo_name),
                )
            }
        };
        url.parse::<Uri>().map_err(Error::from)
    }
}

/// Module to be passed into gitimport that defines how LFS files are imported.
/// The default will disable any LFS support (and the metadata of files pointing to LFS files
/// will be imported, this means that the mononoke repo will mirror the git-repo).
/// Autodetect and each file under MAX_METADATA_LENGTH will be scanned, and if it matched git-lfs
/// metadata file, then the configured lfs_server will be used to try and fetch the data.
#[derive(Debug)]
pub struct GitImportLfsInner {
    /// Server information.
    lfs_server: String,
    /// URL pattern used to construct per-object fetch URLs.
    url_format: LfsServerUrlFormat,
    /// How to deal with the case when the file does not exist on the LFS server.
    /// allow_not_found=false
    ///   A non existing LFS file considered unrecoverable error and bail out
    /// allow_not_found=true
    ///   put the content of the LFS-metafile in its place, and print a warning.
    allow_not_found: bool,
    /// Retries.
    max_attempts: u32,
    time_ms_between_attempts: u32,
    /// Limit the amount of simultaneous connections.
    conn_limit_sem: Option<Arc<Semaphore>>,
    /// Hyperium client we use to connect with
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GitLfsFetchResult {
    Fetched,
    NotFound,
}

impl GitLfsFetchResult {
    pub fn is_fetched(&self) -> bool {
        *self == GitLfsFetchResult::Fetched
    }

    pub fn is_not_found(&self) -> bool {
        *self == GitLfsFetchResult::NotFound
    }
}
#[derive(Clone, Debug, Default)]
pub struct GitImportLfs {
    inner: Option<Arc<GitImportLfsInner>>,
}

impl GitImportLfs {
    pub fn new_disabled() -> Self {
        GitImportLfs { inner: None }
    }
    pub fn new(
        lfs_server: String,
        url_format: LfsServerUrlFormat,
        allow_not_found: bool,
        max_attempts: u32,
        conn_limit: Option<usize>,
        tls_args: Option<TLSArgs>,
    ) -> Result<Self, Error> {
        let mut ssl_connector = SslConnector::builder(SslMethod::tls_client())?;
        if let Some(tls_args) = tls_args {
            ssl_connector.set_ca_file(tls_args.tls_ca)?;
            ssl_connector.set_certificate_file(tls_args.tls_certificate, SslFiletype::PEM)?;
            ssl_connector.set_private_key_file(tls_args.tls_private_key, SslFiletype::PEM)?;
        };
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        let connector =
            HttpsConnector::with_connector(http_connector, ssl_connector).map_err(Error::from)?;

        let client = Client::builder(TokioExecutor::new()).build(connector);
        let inner = GitImportLfsInner {
            lfs_server,
            url_format,
            allow_not_found,
            max_attempts,
            time_ms_between_attempts: 10000,
            conn_limit_sem: conn_limit.map(|x| Arc::new(Semaphore::new(x))),
            client,
        };
        Ok(GitImportLfs {
            inner: Some(Arc::new(inner)),
        })
    }

    /// Checks whether given blob is valid Git LFS pointer and returns its metadata
    pub fn is_lfs_file(&self, gitblob: &[u8], gitid: ObjectId) -> Option<LfsPointerData> {
        if self.inner.is_some() {
            parse_lfs_pointer(gitblob, gitid)
        } else {
            None
        }
    }

    /// Download the LFS file. This works fine with Dewey but should be improved to work
    /// with other backends as well.
    async fn fetch_bytes_internal(
        &self,
        ctx: &CoreContext,
        metadata: &LfsPointerData,
    ) -> Result<
        (
            StoreRequest,
            impl Stream<Item = Result<Bytes, Error>> + Unpin + use<>,
            GitLfsFetchResult,
        ),
        Error,
    > {
        let inner = self.inner.as_ref().ok_or_else(|| {
            format_err!("GitImportLfs::fetch_bytes_internal called on disabled GitImportLfs")
        })?;

        let uri = inner
            .url_format
            .build_object_url(&inner.lfs_server, &metadata.sha256)?;
        let mut req = Request::get(uri.clone())
            .body(Full::new(Bytes::new()))
            .context("creating LFS fetch request")?;
        let client_info = ctx
            .metadata()
            .client_info()
            .cloned()
            .unwrap_or_else(ClientInfo::default);
        req.headers_mut().insert(
            CLIENT_INFO_HEADER,
            HeaderValue::from_str(&client_info.to_json()?)?,
        );
        let resp = inner
            .client
            .request(req)
            .await
            .with_context(|| format!("fetch_bytes_internal {}", uri))?;

        if resp.status().is_success() {
            let bytes = resp.into_body().into_data_stream().map_err(Error::from);
            let sr = StoreRequest::with_sha256(metadata.size, metadata.sha256);
            return Ok((sr, bytes.left_stream(), GitLfsFetchResult::Fetched));
        }
        if resp.status() == StatusCode::NOT_FOUND && inner.allow_not_found {
            warn!(
                "{} not found. Using gitlfs metadata as file content instead.",
                uri,
            );
            let bytes = Bytes::copy_from_slice(&metadata.gitblob);
            let size = metadata.gitblob.len().try_into()?;
            let git_sha1 = hash::RichGitSha1::from_bytes(
                Bytes::copy_from_slice(metadata.gitid.as_bytes()),
                "blob",
                size,
            )?;
            let sr = StoreRequest::with_git_sha1(size, git_sha1);
            return Ok((
                sr,
                stream::once(futures::future::ok(bytes)).right_stream(),
                GitLfsFetchResult::NotFound,
            ));
        }
        Err(format_err!("{} response {:?}", uri, resp))
    }

    async fn fetch_bytes(
        &self,
        ctx: &CoreContext,
        metadata: &LfsPointerData,
    ) -> Result<
        (
            StoreRequest,
            impl Stream<Item = Result<Bytes, Error>> + use<>,
            GitLfsFetchResult,
        ),
        Error,
    > {
        let inner = self.inner.as_ref().ok_or_else(|| {
            format_err!("GitImportLfs::fetch_bytes called on disabled GitImportLfs")
        })?;

        let mut attempt: u32 = 0;
        loop {
            let r = self.fetch_bytes_internal(ctx, metadata).await;
            match r {
                Ok(res) => {
                    return Ok(res);
                }
                Err(err) => {
                    if attempt >= inner.max_attempts {
                        return Err(err);
                    }

                    attempt += 1;
                    // Sleep on average time_ms_between_attempts between attempts.
                    let sleep_time_ms = rand::random_range(0..inner.time_ms_between_attempts * 2);
                    error!(
                        "{}. Attempt {} of {} - Retrying in {} ms",
                        err, attempt, inner.max_attempts, sleep_time_ms,
                    );
                    sleep(Duration::from_millis(sleep_time_ms.into())).await;
                }
            }
        }
    }

    pub async fn with<F, T, Fut>(
        self,
        ctx: CoreContext,
        metadata: LfsPointerData,
        f: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(
                CoreContext,
                LfsPointerData,
                StoreRequest,
                Box<dyn Stream<Item = Result<Bytes, Error>> + Send + Unpin>,
                GitLfsFetchResult,
            ) -> Fut
            + Send
            + 'static,
        T: Send + Sync + 'static,
        Fut: Future<Output = Result<T, Error>> + Send,
    {
        mononoke::spawn_task(async move {
            let inner = self.inner.as_ref().ok_or_else(|| {
                format_err!("GitImportLfs::fetch_bytes_internal called on disabled GitImportLfs")
            })?;

            // If configured a connection limit, grab semaphore lock enforcing it.
            let _slock = if let Some(semaphore) = &inner.conn_limit_sem {
                Some(semaphore.clone().acquire_owned().await?)
            } else {
                None
            };

            let (req, bstream, fetch_result) = self.fetch_bytes(&ctx, &metadata).await?;
            f(ctx, metadata, req, Box::new(bstream), fetch_result).await
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use mononoke_macros::mononoke;

    use super::*;

    fn sha256_fixture() -> hash::Sha256 {
        hash::Sha256::from_byte_array([0xab; 32])
    }

    #[mononoke::test]
    fn dewey_url_shape() {
        let uri = LfsServerUrlFormat::LegacyDewey
            .build_object_url("https://dewey-lfs.example.com", &sha256_fixture())
            .unwrap();
        assert_eq!(
            uri.to_string(),
            format!("https://dewey-lfs.example.com/{}", sha256_fixture()),
        );
    }

    #[mononoke::test]
    fn mononoke_git_lfs_url_shape() {
        let uri = LfsServerUrlFormat::MononokeGitLfs {
            repo_name: "myrepo".to_string(),
        }
        .build_object_url(
            "https://mononoke-git-lfs.internal.tfbnw.net",
            &sha256_fixture(),
        )
        .unwrap();
        assert_eq!(
            uri.to_string(),
            format!(
                "https://mononoke-git-lfs.internal.tfbnw.net/myrepo/download_sha256/{}",
                sha256_fixture(),
            ),
        );
    }

    #[mononoke::test]
    fn mononoke_git_lfs_url_percent_encodes_repo_name() {
        let uri = LfsServerUrlFormat::MononokeGitLfs {
            repo_name: "git/foo/bar".to_string(),
        }
        .build_object_url(
            "https://mononoke-git-lfs.internal.tfbnw.net",
            &sha256_fixture(),
        )
        .unwrap();
        assert_eq!(
            uri.to_string(),
            format!(
                "https://mononoke-git-lfs.internal.tfbnw.net/git%2Ffoo%2Fbar/download_sha256/{}",
                sha256_fixture(),
            ),
        );
    }

    #[mononoke::test]
    fn trailing_slash_in_server_url_does_not_double_up() {
        let uri = LfsServerUrlFormat::LegacyDewey
            .build_object_url("https://dewey-lfs.example.com/", &sha256_fixture())
            .unwrap();
        assert_eq!(
            uri.to_string(),
            format!("https://dewey-lfs.example.com/{}", sha256_fixture()),
        );

        let uri = LfsServerUrlFormat::MononokeGitLfs {
            repo_name: "myrepo".to_string(),
        }
        .build_object_url(
            "https://mononoke-git-lfs.internal.tfbnw.net/",
            &sha256_fixture(),
        )
        .unwrap();
        assert_eq!(
            uri.to_string(),
            format!(
                "https://mononoke-git-lfs.internal.tfbnw.net/myrepo/download_sha256/{}",
                sha256_fixture(),
            ),
        );
    }
}
