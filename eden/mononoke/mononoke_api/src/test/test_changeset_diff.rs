/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Error;
use anyhow::anyhow;
use fbinit::FacebookInit;
use fixtures::ManyFilesDirs;
use fixtures::TestRepoFixture;
use maplit::btreeset;
use mononoke_macros::mononoke;
use mononoke_types::ChangesetId;
use mononoke_types::FileType;
use mononoke_types::GitLfs;
use mononoke_types::path::MPath;
use pretty_assertions::assert_eq;
use tests_utils::CreateCommitContext;
use xdiff::CopyInfo;

use crate::ChangesetContext;
use crate::ChangesetDiffItem;
use crate::ChangesetFileOrdering;
use crate::ChangesetPathDiffContext;
use crate::CoreContext;
use crate::HgChangesetId;
use crate::Mononoke;
use crate::RepoContext;
use crate::changeset::insert_sorted_results;
use crate::repo::MononokeRepo;
use crate::repo::Repo;

#[mononoke::fbinit_test]
async fn test_diff_with_moves(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = test_repo_factory::build_empty(fb).await?;
    let root = CreateCommitContext::new_root(&ctx, &repo)
        .add_file("file_to_move", "context1")
        .commit()
        .await?;

    let commit_with_move = CreateCommitContext::new(&ctx, &repo, vec![root])
        .add_file_with_copy_info("file_moved", "context", (root, "file_to_move"))
        .delete_file("file_to_move")
        .commit()
        .await?;

    let mononoke = Mononoke::new_test(vec![("test".to_string(), repo)]).await?;

    let repo = mononoke
        .repo(ctx.clone(), "test")
        .await?
        .expect("repo exists")
        .build()
        .await?;
    let commit_with_move_ctx = repo
        .changeset(commit_with_move)
        .await?
        .ok_or_else(|| anyhow!("commit not found"))?;
    let diff = commit_with_move_ctx
        .diff_unordered(
            &repo.changeset(root).await?.context("commit not found")?,
            true,  /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
        )
        .await?;

    assert_eq!(diff.len(), 1);
    match diff.first() {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("file_moved")?);
            assert_eq!(
                diff.get_new_content().expect("Should have new").path(),
                &MPath::try_from("file_moved")?
            );
            assert_eq!(
                diff.get_old_content().expect("Should have old").path(),
                &MPath::try_from("file_to_move")?
            );
            assert_eq!(diff.copy_info(), CopyInfo::Move);
        }
        None => {
            panic!("expected a diff");
        }
    }
    Ok(())
}

#[mononoke::fbinit_test]
async fn test_diff_with_multiple_copies(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = test_repo_factory::build_empty(fb).await?;
    let root = CreateCommitContext::new_root(&ctx, &repo)
        .add_file("file_to_copy", "context1")
        .commit()
        .await?;

    let commit_with_copies = CreateCommitContext::new(&ctx, &repo, vec![root])
        .add_file_with_copy_info("copy_one", "context", (root, "file_to_copy"))
        .add_file_with_copy_info("copy_two", "context", (root, "file_to_copy"))
        .commit()
        .await?;

    let mononoke = Mononoke::new_test(vec![("test".to_string(), repo)]).await?;

    let repo = mononoke
        .repo(ctx.clone(), "test")
        .await?
        .expect("repo exists")
        .build()
        .await?;
    let commit_with_copies_ctx = repo
        .changeset(commit_with_copies)
        .await?
        .ok_or_else(|| anyhow!("commit not found"))?;
    let diff = commit_with_copies_ctx
        .diff_unordered(
            &repo.changeset(root).await?.context("commit not found")?,
            true,  /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
        )
        .await?;

    assert_eq!(diff.len(), 2);
    match diff.first() {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("copy_one")?);
            assert_eq!(
                diff.get_new_content().expect("Should have new").path(),
                &MPath::try_from("copy_one")?
            );
            assert_eq!(
                diff.get_old_content().expect("Should have old").path(),
                &MPath::try_from("file_to_copy")?
            );
            assert_eq!(diff.copy_info(), CopyInfo::Copy);
        }
        None => {
            panic!("expected a diff");
        }
    }
    match diff.get(1) {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("copy_two")?);
            assert_eq!(
                diff.get_new_content().expect("Should have new").path(),
                &MPath::try_from("copy_two")?
            );
            assert_eq!(
                diff.get_old_content().expect("Should have old").path(),
                &MPath::try_from("file_to_copy")?
            );
            assert_eq!(diff.copy_info(), CopyInfo::Copy);
        }
        None => {
            panic!("expected a second diff");
        }
    }
    Ok(())
}

#[mononoke::fbinit_test]
async fn test_diff_with_multiple_moves(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = test_repo_factory::build_empty(fb).await?;
    let root = CreateCommitContext::new_root(&ctx, &repo)
        .add_file("file_to_move", "context1")
        .commit()
        .await?;

    let commit_with_moves = CreateCommitContext::new(&ctx, &repo, vec![root])
        .add_file_with_copy_info("copy_one", "context", (root, "file_to_move"))
        .add_file_with_copy_info("copy_two", "context", (root, "file_to_move"))
        .add_file_with_copy_info("copy_zzz", "context", (root, "file_to_move"))
        .delete_file("file_to_move")
        .commit()
        .await?;

    let mononoke = Mononoke::new_test(vec![("test".to_string(), repo)]).await?;

    let repo = mononoke
        .repo(ctx.clone(), "test")
        .await?
        .expect("repo exists")
        .build()
        .await?;
    let commit_with_moves_ctx = repo
        .changeset(commit_with_moves)
        .await?
        .ok_or_else(|| anyhow!("commit not found"))?;
    let diff = commit_with_moves_ctx
        .diff_unordered(
            &repo.changeset(root).await?.context("commit not found")?,
            true,  /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
        )
        .await?;

    assert_eq!(diff.len(), 3);
    // The first copy of the file becomes a move.
    match diff.first() {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("copy_one")?);
            assert_eq!(
                diff.get_new_content().expect("Should have new").path(),
                &MPath::try_from("copy_one")?
            );
            assert_eq!(
                diff.get_old_content().expect("Should have old").path(),
                &MPath::try_from("file_to_move")?
            );
            assert_eq!(diff.copy_info(), CopyInfo::Move);
        }
        None => {
            panic!("expected a diff");
        }
    }
    match diff.get(1) {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("copy_two")?);
            assert_eq!(
                diff.get_new_content().expect("Should have new").path(),
                &MPath::try_from("copy_two")?
            );
            assert_eq!(
                diff.get_old_content().expect("Should have old").path(),
                &MPath::try_from("file_to_move")?
            );
            assert_eq!(diff.copy_info(), CopyInfo::Copy);
        }
        None => {
            panic!("expected a second diff");
        }
    }
    match diff.get(2) {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("copy_zzz")?);
            assert_eq!(
                diff.get_new_content().expect("Should have new").path(),
                &MPath::try_from("copy_zzz")?
            );
            assert_eq!(
                diff.get_old_content().expect("Should have old").path(),
                &MPath::try_from("file_to_move")?
            );
            assert_eq!(diff.copy_info(), CopyInfo::Copy);
        }
        None => {
            panic!("expected a third diff");
        }
    }
    Ok(())
}

#[mononoke::fbinit_test]
async fn test_diff_with_dirs(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let mononoke = Mononoke::new_test(vec![(
        "test".to_string(),
        ManyFilesDirs::get_repo(fb).await,
    )])
    .await?;
    let repo = mononoke
        .repo(ctx, "test")
        .await?
        .expect("repo exists")
        .build()
        .await?;

    // Case one: dirs added
    let cs_id = HgChangesetId::from_str("d261bc7900818dea7c86935b3fb17a33b2e3a6b4")?;
    let cs = repo.changeset(cs_id).await?.expect("changeset exists");
    let other_cs_id = HgChangesetId::from_str("5a28e25f924a5d209b82ce0713d8d83e68982bc8")?;
    let other_cs = repo
        .changeset(other_cs_id)
        .await?
        .expect("other changeset exists");

    let mut diff: Vec<_> = cs
        .diff_unordered(
            &other_cs,
            false,
            false,
            None,
            btreeset! {ChangesetDiffItem::TREES},
        )
        .await?;
    diff.sort_by(|a, b| a.path().cmp(b.path()));
    assert_eq!(diff.len(), 6);
    match diff.first() {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("")?);
            assert_eq!(
                diff.get_new_content().unwrap().path(),
                &MPath::try_from("")?
            );
            assert_eq!(
                diff.get_old_content().unwrap().path(),
                &MPath::try_from("")?
            );
        }
        None => {
            panic!("expected a root dir diff");
        }
    }
    match diff.get(1) {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("dir1")?);
        }
        None => {
            panic!("expected a diff");
        }
    }

    // Case two: dir (with subdirs) replaced with file
    let cs_id = HgChangesetId::from_str("051946ed218061e925fb120dac02634f9ad40ae2")?;
    let cs = repo.changeset(cs_id).await?.expect("changeset exists");
    let other_cs_id = HgChangesetId::from_str("d261bc7900818dea7c86935b3fb17a33b2e3a6b4")?;
    let other_cs = repo
        .changeset(other_cs_id)
        .await?
        .expect("other changeset exists");

    // Added
    let mut diff: Vec<_> = cs
        .diff_unordered(
            &other_cs,
            false,
            false,
            None,
            btreeset! {ChangesetDiffItem::TREES},
        )
        .await?;
    diff.sort_by(|a, b| a.path().cmp(b.path()));
    assert_eq!(diff.len(), 5);
    match diff.first() {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("")?);
            assert_eq!(
                diff.get_new_content().unwrap().path(),
                &MPath::try_from("")?
            );
            assert_eq!(
                diff.get_old_content().unwrap().path(),
                &MPath::try_from("")?
            );
        }
        None => {
            panic!("expected a root dir diff");
        }
    }
    match diff.get(1) {
        Some(diff) => {
            assert_eq!(diff.path(), &MPath::try_from("dir1")?);
            assert!(diff.get_new_content().is_none());
            assert_eq!(
                diff.get_old_content().unwrap().path(),
                &MPath::try_from("dir1")?
            );
        }
        None => {
            panic!("expected a diff");
        }
    }

    Ok(())
}

fn check_diff_paths<R: MononokeRepo>(diff_ctxs: &[ChangesetPathDiffContext<R>], paths: &[&str]) {
    let diff_paths = diff_ctxs
        .iter()
        .map(|diff_ctx| {
            if let (Some(to), Some(from)) = (diff_ctx.get_new_content(), diff_ctx.get_old_content())
            {
                if diff_ctx.copy_info() == CopyInfo::None {
                    assert_eq!(
                        from.path(),
                        to.path(),
                        "paths for changed file do not match"
                    );
                } else {
                    assert_ne!(
                        from.path(),
                        to.path(),
                        "paths for copied or moved file should not match"
                    );
                }
            }
            diff_ctx.path().to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(diff_paths, paths,);
}

#[mononoke::fbinit_test]
async fn test_ordered_diff(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = test_repo_factory::build_empty(fb).await?;
    let root = CreateCommitContext::new_root(&ctx, &repo)
        .add_file("root", "root")
        .commit()
        .await?;

    // List of file names to test in repo order.  Note in particular that
    // "j.txt" is after "j/k" even though "." is before "/" in lexicographic
    // order, as we sort based on the directory name ("j").
    let file_list = [
        "!", "0", "1", "10", "2", "a/a/a/a", "a/a/a/b", "d/e", "d/g", "i", "j/k", "j.txt", "p",
        "r/s/t/u", "r/v", "r/w/x", "r/y", "z", "é",
    ];

    let mut commit = CreateCommitContext::new(&ctx, &repo, vec![root]);
    for file in file_list.iter() {
        commit = commit.add_file(*file, *file);
    }
    let commit = commit.commit().await?;

    let mononoke = Mononoke::new_test(vec![("test".to_string(), repo.clone())]).await?;

    let repo_ctx = mononoke
        .repo(ctx.clone(), "test")
        .await?
        .expect("repo exists")
        .build()
        .await?;
    let commit_ctx = repo_ctx
        .changeset(commit)
        .await?
        .ok_or_else(|| anyhow!("commit not found"))?;
    let root_ctx = &repo_ctx
        .changeset(root)
        .await?
        .context("commit not found")?;
    let diff = commit_ctx
        .diff(
            root_ctx,
            false, /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            None,
        )
        .await?;

    check_diff_paths(&diff, &file_list);

    // Test limits and continuation.
    let diff = commit_ctx
        .diff(
            root_ctx,
            false, /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            Some(8),
        )
        .await?;
    check_diff_paths(&diff, &file_list[..8]);
    let diff = commit_ctx
        .diff(
            root_ctx,
            false, /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered {
                after: Some(file_list[7].try_into()?),
            },
            Some(8),
        )
        .await?;
    check_diff_paths(&diff, &file_list[8..16]);
    let diff = commit_ctx
        .diff(
            root_ctx,
            false, /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered {
                after: Some(file_list[15].try_into()?),
            },
            Some(8),
        )
        .await?;
    check_diff_paths(&diff, &file_list[16..]);

    let mod_file_list = [
        "1", "d/e", "d/g", "i/ii", "j/k", "j.txt", "p", "r/v", "r/w/y", "z",
    ];
    let del_file_list = ["10", "i", "r/w/x", "r/y"];

    let mut all_file_list = mod_file_list
        .iter()
        .chain(del_file_list.iter())
        .map(Deref::deref)
        .collect::<Vec<_>>();
    all_file_list.sort_unstable();

    let mut commit2 = CreateCommitContext::new(&ctx, &repo, vec![commit]);
    for file in mod_file_list.iter() {
        commit2 = commit2.add_file(*file, "modified");
    }
    commit2 = commit2
        .add_file_with_copy_info("d/f", "copied", (commit, "d/g"))
        .add_file_with_copy_info("q/y", "moved", (commit, "r/y"));
    for file in del_file_list.iter() {
        commit2 = commit2.delete_file(*file);
    }
    let commit2 = commit2.commit().await?;

    let commit2_ctx = repo_ctx
        .changeset(commit2)
        .await?
        .ok_or_else(|| anyhow!("commit not found"))?;
    let diff = commit2_ctx
        .diff(
            &commit_ctx,
            true,  /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            None,
        )
        .await?;

    let all_file_list = [
        "1", "10", "d/e", "d/f", "d/g", "i", "i/ii", "j/k", "j.txt", "p", "q/y", "r/v", "r/w/x",
        "r/w/y", "z",
    ];
    check_diff_paths(&diff, &all_file_list);

    // Diff including trees.
    let diff = commit2_ctx
        .diff(
            &commit_ctx,
            true,  /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES, ChangesetDiffItem::TREES},
            ChangesetFileOrdering::Ordered { after: None },
            None,
        )
        .await?;

    // "i" is listed twice as a file that is deleted and a tree that is added
    let all_file_and_dir_list = [
        "", "1", "10", "d", "d/e", "d/f", "d/g", "i", "i", "i/ii", "j", "j/k", "j.txt", "p", "q",
        "q/y", "r", "r/v", "r/w", "r/w/x", "r/w/y", "z",
    ];
    check_diff_paths(&diff, &all_file_and_dir_list);

    // Diff over two commits of trees.
    let diff = commit2_ctx
        .diff(
            root_ctx,
            false, /* include_copies_renames */
            false, /* include_subtree_copies */
            None,  /* path_restrictions */
            btreeset! {ChangesetDiffItem::TREES},
            ChangesetFileOrdering::Ordered { after: None },
            None,
        )
        .await?;

    let all_changed_dirs_list = [
        "", "a", "a/a", "a/a/a", "d", "i", "j", "q", "r", "r/s", "r/s/t", "r/w",
    ];
    check_diff_paths(&diff, &all_changed_dirs_list);

    // Diff over two commits, filtered by prefix and with a limit.
    let path_restrictions = Some(vec![
        "1".try_into()?,
        "a/a".try_into()?,
        "q".try_into()?,
        "r/s".try_into()?,
    ]);
    let diff = commit2_ctx
        .diff(
            root_ctx,
            false, /* include_copies_renames */
            false, /* include_subtree_copies */
            path_restrictions.clone(),
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            Some(3),
        )
        .await?;

    let filtered_changed_files_list = ["1", "a/a/a/a", "a/a/a/b", "q/y", "r/s/t/u"];
    check_diff_paths(&diff, &filtered_changed_files_list[..3]);

    let diff = commit2_ctx
        .diff(
            root_ctx,
            false, /* include_copies_renames */
            false, /* include_subtree_copies */
            path_restrictions,
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered {
                after: Some(filtered_changed_files_list[2].try_into()?),
            },
            Some(3),
        )
        .await?;

    check_diff_paths(&diff, &filtered_changed_files_list[3..]);
    Ok(())
}

#[mononoke::fbinit_test]
async fn test_ordered_root_diff(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = test_repo_factory::build_empty(fb).await?;

    // List of file names to test in repo order.  Note in particular that
    // "j.txt" is after "j/k" even though "." is before "/" in lexicographic
    // order, as we sort based on the directory name ("j").
    let file_list = [
        "!", "0", "1", "10", "2", "a/a/a/a", "a/a/a/b", "d/e", "d/g", "i", "j/k", "j.txt", "p",
        "r/s/t/u", "r/v", "r/w/x", "r/y", "z", "é",
    ];

    let mut root = CreateCommitContext::new_root(&ctx, &repo);

    for file in file_list.iter() {
        root = root.add_file(*file, *file);
    }
    let commit = root.commit().await?;

    let mononoke = Mononoke::new_test(vec![("test".to_string(), repo.clone())]).await?;

    let repo_ctx = mononoke
        .repo(ctx.clone(), "test")
        .await?
        .expect("repo exists")
        .build()
        .await?;
    let commit_ctx = repo_ctx
        .changeset(commit)
        .await?
        .ok_or_else(|| anyhow!("commit not found"))?;

    let diff = commit_ctx
        .diff_root(
            None, /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            None, /* limit */
        )
        .await?;
    check_diff_paths(&diff, &file_list);

    // Test limits and continuation.
    let diff = commit_ctx
        .diff_root(
            None, /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            Some(8),
        )
        .await?;
    check_diff_paths(&diff, &file_list[..8]);

    let diff = commit_ctx
        .diff_root(
            None, /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered {
                after: Some(file_list[7].try_into()?),
            },
            Some(8),
        )
        .await?;
    check_diff_paths(&diff, &file_list[8..16]);

    let diff = commit_ctx
        .diff_root(
            None, /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered {
                after: Some(file_list[15].try_into()?),
            },
            Some(8),
        )
        .await?;
    check_diff_paths(&diff, &file_list[16..]);

    let path_restrictions = Some(vec![
        "1".try_into()?,
        "a/a".try_into()?,
        "q".try_into()?,
        "r/s".try_into()?,
    ]);
    let diff = commit_ctx
        .diff_root(
            path_restrictions.clone(),
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            Some(3),
        )
        .await?;

    let filtered_changed_files_list = ["1", "a/a/a/a", "a/a/a/b", "q/y", "r/s/t/u"];
    check_diff_paths(&diff, &filtered_changed_files_list[..3]);

    let diff = commit_ctx
        .diff_root(
            None, /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES, ChangesetDiffItem::TREES},
            ChangesetFileOrdering::Ordered { after: None },
            None, /* limit */
        )
        .await?;

    let files_dirs_list = [
        "!", "0", "1", "10", "2", "a", "a/a", "a/a/a", "a/a/a/a", "a/a/a/b", "d", "d/e", "d/g",
        "i", "j", "j/k", "j.txt", "p", "r", "r/s", "r/s/t", "r/s/t/u", "r/v", "r/w", "r/w/x",
        "r/y", "z", "é",
    ];
    check_diff_paths(&diff, &files_dirs_list);

    let diff = commit_ctx
        .diff_root(
            None, /* path_restrictions */
            btreeset! {ChangesetDiffItem::TREES},
            ChangesetFileOrdering::Ordered { after: None },
            None, /* limit */
        )
        .await?;

    let dirs_list = ["a", "a/a", "a/a/a", "d", "j", "r", "r/s", "r/s/t", "r/w"];
    check_diff_paths(&diff, &dirs_list);

    // a non-root commit2
    let commit2 = CreateCommitContext::new(&ctx, &repo, vec![commit])
        .add_file("second_file", "second_file")
        .delete_file("!")
        .delete_file("0")
        .delete_file("j/k")
        .commit()
        .await?;

    // commit2
    let commit2_ctx = repo_ctx
        .changeset(commit2)
        .await?
        .ok_or_else(|| anyhow!("commit not found"))?;

    let diff = commit2_ctx
        .diff_root(
            None, /* path_restrictions */
            btreeset! {ChangesetDiffItem::FILES},
            ChangesetFileOrdering::Ordered { after: None },
            None,
        )
        .await?;

    let second_commit_files_list = [
        "1",
        "10",
        "2",
        "a/a/a/a",
        "a/a/a/b",
        "d/e",
        "d/g",
        "i",
        "j.txt",
        "p",
        "r/s/t/u",
        "r/v",
        "r/w/x",
        "r/y",
        "second_file",
        "z",
        "é",
    ];
    check_diff_paths(&diff, &second_commit_files_list);

    Ok(())
}

async fn build_lfs_enabled_repo(fb: FacebookInit) -> Result<Repo, Error> {
    Ok(test_repo_factory::TestRepoFactory::new(fb)?
        .with_config_override(|cfg| {
            cfg.git_configs.git_lfs_interpret_pointers = true;
        })
        .build()
        .await?)
}

async fn repo_ctx_for_test(ctx: &CoreContext, repo: Repo) -> Result<RepoContext<Repo>, Error> {
    Ok(RepoContext::new_test(ctx.clone(), Arc::new(repo)).await?)
}

async fn changeset_ctx(
    repo_ctx: &RepoContext<Repo>,
    changeset_id: ChangesetId,
    name: &str,
) -> Result<ChangesetContext<Repo>, Error> {
    repo_ctx
        .changeset(changeset_id)
        .await?
        .ok_or_else(|| anyhow!("{name} changeset not found"))
}

async fn build_lfs_flip_pair(
    ctx: &CoreContext,
    repo: &Repo,
    old_lfs: GitLfs,
    new_lfs: GitLfs,
) -> Result<(ChangesetId, ChangesetId), Error> {
    let parent = CreateCommitContext::new_root(ctx, repo)
        .add_file_with_type_and_lfs("binary_file", "shared blob", FileType::Regular, old_lfs)
        .commit()
        .await?;
    let child = CreateCommitContext::new(ctx, repo, vec![parent])
        .add_file_with_type_and_lfs("binary_file", "shared blob", FileType::Regular, new_lfs)
        .commit()
        .await?;

    Ok((parent, child))
}

async fn lfs_change_paths(
    changeset: &ChangesetContext<Repo>,
    other: &ChangesetContext<Repo>,
    path_restrictions: Option<Vec<MPath>>,
) -> Result<Vec<String>, Error> {
    let subtree_copy_sources = manifest::PathTree::default();
    let excluded_paths = std::collections::HashSet::new();
    Ok(changeset
        .get_potential_lfs_changes(
            other,
            &path_restrictions,
            &subtree_copy_sources,
            &excluded_paths,
            None,
            None,
            usize::MAX,
        )
        .await?
        .into_iter()
        .map(|diff| diff.path().to_string())
        .collect())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_detects_lfs_flip(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let (parent, child) = build_lfs_flip_pair(
        &ctx,
        &repo,
        GitLfs::FullContent,
        GitLfs::canonical_pointer(),
    )
    .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    assert_eq!(
        lfs_change_paths(&child_ctx, &parent_ctx, None).await?,
        vec!["binary_file"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_detects_executable_lfs_flip(
    fb: FacebookInit,
) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let parent = CreateCommitContext::new_root(&ctx, &repo)
        .add_file_with_type_and_lfs(
            "binary_exe",
            "shared blob",
            FileType::Executable,
            GitLfs::FullContent,
        )
        .commit()
        .await?;
    let child = CreateCommitContext::new(&ctx, &repo, vec![parent])
        .add_file_with_type_and_lfs(
            "binary_exe",
            "shared blob",
            FileType::Executable,
            GitLfs::canonical_pointer(),
        )
        .commit()
        .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    assert_eq!(
        lfs_change_paths(&child_ctx, &parent_ctx, None).await?,
        vec!["binary_exe"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_detects_immediate_parent_de_lfs_flip(
    fb: FacebookInit,
) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let (parent, child) = build_lfs_flip_pair(
        &ctx,
        &repo,
        GitLfs::canonical_pointer(),
        GitLfs::FullContent,
    )
    .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    assert_eq!(
        lfs_change_paths(&child_ctx, &parent_ctx, None).await?,
        vec!["binary_file"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_detects_inherited_across_merge(
    fb: FacebookInit,
) -> Result<(), Error> {
    // The path's LFS state was set at root, then inherited unchanged across
    // a merge before the immediate parent. The supplement still detects the
    // renormalize-up flip: the candidate filter sees the LFS-pointer change
    // in the child's bonsai, and the manifest leaves match because LFS
    // pointers and raw blobs share the same effective content_id.
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;

    let root = CreateCommitContext::new_root(&ctx, &repo)
        .add_file_with_type_and_lfs(
            "binary_file",
            "shared blob",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .add_file("anchor", "root")
        .commit()
        .await?;
    let p0 = CreateCommitContext::new(&ctx, &repo, vec![root])
        .add_file("p0_marker", "p0")
        .commit()
        .await?;
    let p1 = CreateCommitContext::new(&ctx, &repo, vec![root])
        .add_file("p1_marker", "p1")
        .commit()
        .await?;
    let merge = CreateCommitContext::new(&ctx, &repo, vec![p0, p1])
        .add_file("merge_marker", "m")
        .commit()
        .await?;
    let child = CreateCommitContext::new(&ctx, &repo, vec![merge])
        .add_file_with_type_and_lfs(
            "binary_file",
            "shared blob",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .commit()
        .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let merge_ctx = changeset_ctx(&repo_ctx, merge, "merge").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    assert_eq!(
        lfs_change_paths(&child_ctx, &merge_ctx, None).await?,
        vec!["binary_file"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_emits_re_recorded_state(
    fb: FacebookInit,
) -> Result<(), Error> {
    // Documents the producer-invariant assumption: if a commit synthetically
    // re-records a `Change` with the same content+type+LFS as the parent's
    // effective state, the supplement reports it as a flip. Real producers
    // (git import, Sapling commits, the renormalization tool) never emit
    // such no-op entries -- they only record actual changes -- so this case
    // is unreachable in production. If that invariant ever breaks, this
    // test will keep emitting and downstream consumers will see spurious
    // "changed" paths.
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let a = CreateCommitContext::new_root(&ctx, &repo)
        .add_file_with_type_and_lfs(
            "binary_file",
            "shared blob",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .add_file("anchor", "a")
        .commit()
        .await?;
    let b = CreateCommitContext::new(&ctx, &repo, vec![a])
        .add_file("anchor", "b")
        .commit()
        .await?;
    let c = CreateCommitContext::new(&ctx, &repo, vec![b])
        .add_file_with_type_and_lfs(
            "binary_file",
            "shared blob",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .commit()
        .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let b_ctx = changeset_ctx(&repo_ctx, b, "B").await?;
    let c_ctx = changeset_ctx(&repo_ctx, c, "C").await?;

    assert_eq!(
        lfs_change_paths(&c_ctx, &b_ctx, None).await?,
        vec!["binary_file"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_skips_inherited_de_lfs_flip(
    fb: FacebookInit,
) -> Result<(), Error> {
    // De-LFS direction (pointer -> raw) where the immediate parent did NOT
    // record an LFS marker for the path. The prefilter requires either side
    // to record an LFS marker, so this case is intentionally skipped — a
    // documented limitation.
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let a = CreateCommitContext::new_root(&ctx, &repo)
        .add_file_with_type_and_lfs(
            "binary_file",
            "shared blob",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .add_file("anchor", "a")
        .commit()
        .await?;
    let b = CreateCommitContext::new(&ctx, &repo, vec![a])
        .add_file("anchor", "b")
        .commit()
        .await?;
    let c = CreateCommitContext::new(&ctx, &repo, vec![b])
        .add_file_with_type_and_lfs(
            "binary_file",
            "shared blob",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .commit()
        .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let b_ctx = changeset_ctx(&repo_ctx, b, "B").await?;
    let c_ctx = changeset_ctx(&repo_ctx, c, "C").await?;

    assert_eq!(
        lfs_change_paths(&c_ctx, &b_ctx, None).await?,
        Vec::<String>::new(),
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_excludes_non_lfs_changes(
    fb: FacebookInit,
) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let parent = CreateCommitContext::new_root(&ctx, &repo)
        .add_file_with_type_and_lfs(
            "raw_file",
            "raw content",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .add_file_with_type_and_lfs(
            "lfs_file",
            "shared",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .commit()
        .await?;
    let child = CreateCommitContext::new(&ctx, &repo, vec![parent])
        .add_file_with_type_and_lfs(
            "raw_file",
            "raw content",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .add_file_with_type_and_lfs("lfs_file", "shared", FileType::Regular, GitLfs::FullContent)
        .commit()
        .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    assert_eq!(
        lfs_change_paths(&child_ctx, &parent_ctx, None).await?,
        vec!["lfs_file"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_respects_path_restrictions(
    fb: FacebookInit,
) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let parent = CreateCommitContext::new_root(&ctx, &repo)
        .add_file_with_type_and_lfs(
            "included/lfs_file",
            "shared",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .add_file_with_type_and_lfs(
            "excluded/lfs_file",
            "shared",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .commit()
        .await?;
    let child = CreateCommitContext::new(&ctx, &repo, vec![parent])
        .add_file_with_type_and_lfs(
            "included/lfs_file",
            "shared",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .add_file_with_type_and_lfs(
            "excluded/lfs_file",
            "shared",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .commit()
        .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    let restrictions = Some(vec![MPath::try_from("included")?]);
    assert_eq!(
        lfs_change_paths(&child_ctx, &parent_ctx, restrictions).await?,
        vec!["included/lfs_file"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_get_potential_lfs_changes_returns_empty_when_repo_lfs_disabled(
    fb: FacebookInit,
) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = test_repo_factory::build_empty(fb).await?;
    let (parent, child) = build_lfs_flip_pair(
        &ctx,
        &repo,
        GitLfs::FullContent,
        GitLfs::canonical_pointer(),
    )
    .await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    assert_eq!(
        lfs_change_paths(&child_ctx, &parent_ctx, None).await?,
        Vec::<String>::new(),
    );

    Ok(())
}

/// Build a fixture repo with both manifest-emitted changes (different
/// content at `a_changed` and `c_changed`) and an LFS-only flip
/// (`b_lfs_only`) between two commits.
async fn build_renormalize_with_content_changes(
    ctx: &CoreContext,
    repo: &Repo,
) -> Result<(ChangesetId, ChangesetId), Error> {
    let parent = CreateCommitContext::new_root(ctx, repo)
        .add_file_with_type_and_lfs(
            "a_changed",
            "content A1",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .add_file_with_type_and_lfs(
            "b_lfs_only",
            "shared blob",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .add_file_with_type_and_lfs(
            "c_changed",
            "content C1",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .commit()
        .await?;
    let child = CreateCommitContext::new(ctx, repo, vec![parent])
        .add_file_with_type_and_lfs(
            "a_changed",
            "content A2",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .add_file_with_type_and_lfs(
            "b_lfs_only",
            "shared blob",
            FileType::Regular,
            GitLfs::canonical_pointer(),
        )
        .add_file_with_type_and_lfs(
            "c_changed",
            "content C2",
            FileType::Regular,
            GitLfs::FullContent,
        )
        .commit()
        .await?;
    Ok((parent, child))
}

async fn diff_files_only(
    changeset: &ChangesetContext<Repo>,
    other: &ChangesetContext<Repo>,
    ordering: ChangesetFileOrdering,
) -> Result<Vec<ChangesetPathDiffContext<Repo>>, Error> {
    Ok(changeset
        .diff(
            other,
            false,
            false,
            None,
            btreeset! {ChangesetDiffItem::FILES},
            ordering,
            None,
        )
        .await?)
}

async fn supplement_for(
    child: &ChangesetContext<Repo>,
    parent: &ChangesetContext<Repo>,
) -> Result<Vec<ChangesetPathDiffContext<Repo>>, Error> {
    let subtree_copy_sources = manifest::PathTree::default();
    let excluded_paths = std::collections::HashSet::new();
    Ok(child
        .get_potential_lfs_changes(
            parent,
            &None,
            &subtree_copy_sources,
            &excluded_paths,
            None,
            None,
            usize::MAX,
        )
        .await?)
}

fn paths_of<R: MononokeRepo>(diffs: &[ChangesetPathDiffContext<R>]) -> Vec<String> {
    diffs.iter().map(|d| d.path().to_string()).collect()
}

#[mononoke::fbinit_test]
async fn test_insert_sorted_results_ordered_interleaves_by_path(
    fb: FacebookInit,
) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let (parent, child) = build_renormalize_with_content_changes(&ctx, &repo).await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    let mut manifest_vec = diff_files_only(
        &child_ctx,
        &parent_ctx,
        ChangesetFileOrdering::Ordered { after: None },
    )
    .await?;
    // Manifest walk sees only the two content-changed paths.
    assert_eq!(paths_of(&manifest_vec), vec!["a_changed", "c_changed"]);

    let supplement = supplement_for(&child_ctx, &parent_ctx).await?;
    assert_eq!(paths_of(&supplement), vec!["b_lfs_only"]);

    insert_sorted_results(&mut manifest_vec, supplement, true);
    assert_eq!(
        paths_of(&manifest_vec),
        vec!["a_changed", "b_lfs_only", "c_changed"],
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_insert_sorted_results_unordered_appends(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let (parent, child) = build_renormalize_with_content_changes(&ctx, &repo).await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    let mut manifest_vec =
        diff_files_only(&child_ctx, &parent_ctx, ChangesetFileOrdering::Unordered).await?;
    let manifest_len_before = manifest_vec.len();
    let supplement = supplement_for(&child_ctx, &parent_ctx).await?;
    assert_eq!(paths_of(&supplement), vec!["b_lfs_only"]);

    insert_sorted_results(&mut manifest_vec, supplement, false);
    assert_eq!(manifest_vec.len(), manifest_len_before + 1);
    assert!(
        paths_of(&manifest_vec).contains(&"b_lfs_only".to_string()),
        "supplement path should be appended in unordered mode",
    );

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_insert_sorted_results_empty_supplement_no_op(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let (parent, child) = build_renormalize_with_content_changes(&ctx, &repo).await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    let mut manifest_vec = diff_files_only(
        &child_ctx,
        &parent_ctx,
        ChangesetFileOrdering::Ordered { after: None },
    )
    .await?;
    let before = paths_of(&manifest_vec);

    insert_sorted_results(&mut manifest_vec, Vec::new(), true);
    assert_eq!(paths_of(&manifest_vec), before);

    insert_sorted_results(&mut manifest_vec, Vec::new(), false);
    assert_eq!(paths_of(&manifest_vec), before);

    Ok(())
}

#[mononoke::fbinit_test]
async fn test_insert_sorted_results_empty_manifest(fb: FacebookInit) -> Result<(), Error> {
    let ctx = CoreContext::test_mock(fb);
    let repo: Repo = build_lfs_enabled_repo(fb).await?;
    let (parent, child) = build_renormalize_with_content_changes(&ctx, &repo).await?;

    let repo_ctx = repo_ctx_for_test(&ctx, repo).await?;
    let parent_ctx = changeset_ctx(&repo_ctx, parent, "parent").await?;
    let child_ctx = changeset_ctx(&repo_ctx, child, "child").await?;

    let supplement = supplement_for(&child_ctx, &parent_ctx).await?;
    let supplement_paths = paths_of(&supplement);

    let mut manifest_vec: Vec<ChangesetPathDiffContext<Repo>> = Vec::new();
    insert_sorted_results(&mut manifest_vec, supplement, true);
    assert_eq!(paths_of(&manifest_vec), supplement_paths);

    Ok(())
}
