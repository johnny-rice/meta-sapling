# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This software may be used and distributed according to the terms of the
# GNU General Public License found in the LICENSE file in the root
# directory of this source tree.

  $ . "${TEST_FIXTURES}/library.sh"

  $ cat >> "$ACL_FILE" << ACLS
  > {
  >   "repos": {
  >     "orig": {
  >       "actions": {
  >         "read": ["$CLIENT0_ID_TYPE:$CLIENT0_ID_DATA", "X509_SUBJECT_NAME:CN=localhost,O=Mononoke,C=US,ST=CA", "X509_SUBJECT_NAME:CN=client0,O=Mononoke,C=US,ST=CA"],
  >         "write": ["$CLIENT0_ID_TYPE:$CLIENT0_ID_DATA", "X509_SUBJECT_NAME:CN=localhost,O=Mononoke,C=US,ST=CA", "X509_SUBJECT_NAME:CN=client0,O=Mononoke,C=US,ST=CA"],
  >         "bypass_readonly": ["$CLIENT0_ID_TYPE:$CLIENT0_ID_DATA", "X509_SUBJECT_NAME:CN=localhost,O=Mononoke,C=US,ST=CA", "X509_SUBJECT_NAME:CN=client0,O=Mononoke,C=US,ST=CA"]
  >       }
  >     },
  >     "orig_shadow": {
  >       "actions": {
  >         "read": ["$CLIENT0_ID_TYPE:$CLIENT0_ID_DATA","SERVICE_IDENTITY:server", "X509_SUBJECT_NAME:CN=localhost,O=Mononoke,C=US,ST=CA", "X509_SUBJECT_NAME:CN=client0,O=Mononoke,C=US,ST=CA"],
  >         "write": ["$CLIENT0_ID_TYPE:$CLIENT0_ID_DATA","SERVICE_IDENTITY:server", "X509_SUBJECT_NAME:CN=localhost,O=Mononoke,C=US,ST=CA", "X509_SUBJECT_NAME:CN=client0,O=Mononoke,C=US,ST=CA"],
  >          "bypass_readonly": ["$CLIENT0_ID_TYPE:$CLIENT0_ID_DATA","SERVICE_IDENTITY:server", "X509_SUBJECT_NAME:CN=localhost,O=Mononoke,C=US,ST=CA", "X509_SUBJECT_NAME:CN=client0,O=Mononoke,C=US,ST=CA"]
  >       }
  >     }
  >   },
  >   "tiers": {
  >     "mirror_commit_upload": {
  >       "actions": {
  >         "mirror_upload": ["$CLIENT0_ID_TYPE:$CLIENT0_ID_DATA","SERVICE_IDENTITY:server", "X509_SUBJECT_NAME:CN=localhost,O=Mononoke,C=US,ST=CA", "X509_SUBJECT_NAME:CN=client0,O=Mononoke,C=US,ST=CA"]
  >       }
  >     }
  >   }
  > }
  > ACLS

  $ REPOID=0 REPONAME=orig ACL_NAME=orig setup_common_config
  $ REPOID=1 REPONAME=orig_shadow ACL_NAME=orig_shadow setup_common_config

  $ start_and_wait_for_mononoke_server

  $ hg clone -q mono:orig orig
  $ cd orig
  $ drawdag << EOS
  > E # E/dir1/dir2/fifth = abcdefg\n
  > |
  > D # D/dir1/dir2/forth = abcdef\n
  > |
  > C # C/dir1/dir2/third = abcde\n (copied from dir1/dir2/first)
  > |
  > B # B/dir1/dir2/second = abcd\n
  > |
  > A # A/dir1/dir2/first = abc\n
  > EOS


  $ hg goto A -q
  $ hg push -r . --to master_bookmark -q --create

  $ hg goto E -q
  $ hg push -r . --to master_bookmark -q

  $ hg log > $TESTTMP/hglog.out

Sync all bookmarks moves
  $ with_stripped_logs mononoke_modern_sync sync-once orig orig_shadow --start-id 0
  Running sync-once loop
  Connecting to https://localhost:$LOCAL_PORT/edenapi/
  Established EdenAPI connection
  Initialized channels
  Calculating segments for entry 1
  Skipping 0 commits, starting sync of 1 commits 
  Uploaded changesets: [HgChangesetId(HgId("e20237022b1290d98c3f14049931a8f498c18c53"))]
  Moved bookmark with result SetBookmarkResponse { data: Ok(()) }
  Calculating segments for entry 2
  Skipping 0 commits, starting sync of 4 commits 
  Uploaded changesets: [HgChangesetId(HgId("5a95ef0f59a992dcb5385649217862599de05565"))]
  Uploaded changesets: [HgChangesetId(HgId("fc03e5f3125836eb107f2fa5b070f841d0b62b85"))]
  Uploaded changesets: [HgChangesetId(HgId("2571175c538cc794dc974c705fcb12bc848efab4"))]
  Uploaded changesets: [HgChangesetId(HgId("8c3947e5d8bd4fe70259eca001b8885651c75850"))]
  Moved bookmark with result SetBookmarkResponse { data: Ok(()) }

  $ mononoke_admin mutable-counters --repo-name orig get modern_sync
  Some(2)
  $ cat  $TESTTMP/modern_sync_scuba_logs | jq | rg "start_id|dry_run|repo"
      "start_id": 0,
      "dry_run": "false",
      "repo": "orig"* (glob)

  $ cd ..

  $ hg clone -q mono:orig_shadow orig_shadow --noupdate
  $ cd orig_shadow
  $ hg pull
  pulling from mono:orig_shadow

  $ hg log > $TESTTMP/hglog2.out
  $ hg up master_bookmark
  10 files updated, 0 files merged, 0 files removed, 0 files unresolved
  $ ls dir1/dir2
  fifth
  first
  forth
  second
  third

  $ diff  $TESTTMP/hglog.out  $TESTTMP/hglog2.out

  $ mononoke_admin repo-info  --repo-name orig_shadow --show-commit-count
  Repo: orig_shadow
  Repo-Id: 1
  Main-Bookmark: master (not set)
  Commits: 5 (Public: 0, Draft: 5)

// Try to re-sync and hit error cause bookmark can't be re-written
  $ with_stripped_logs mononoke_modern_sync sync-once orig orig_shadow --start-id 0
  Running sync-once loop
  Connecting to https://localhost:$LOCAL_PORT/edenapi/
  Established EdenAPI connection
  Initialized channels
  Calculating segments for entry 1
  Skipping 1 commits, starting sync of 0 commits 
  Moved bookmark with result SetBookmarkResponse { data: Ok(()) }
  Calculating segments for entry 2
  Skipping 4 commits, starting sync of 0 commits 
  Moved bookmark with result SetBookmarkResponse { data: Ok(()) }
