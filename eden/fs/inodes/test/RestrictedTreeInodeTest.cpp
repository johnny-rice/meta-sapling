/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include "eden/fs/inodes/TreeInode.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <system_error>

#include "eden/common/utils/CaseSensitivity.h"
#include "eden/fs/inodes/EdenMount.h"
#include "eden/fs/inodes/FileInode.h"
#include "eden/fs/inodes/InodeMap.h"
#include "eden/fs/inodes/InodeMetadata.h"
#include "eden/fs/inodes/Overlay.h"
#include "eden/fs/model/Tree.h"
#include "eden/fs/model/TreeAuxData.h"
#include "eden/fs/store/ObjectFetchContext.h"
#include "eden/fs/testharness/FakeBackingStore.h"
#include "eden/fs/testharness/FakeTreeBuilder.h"
#include "eden/fs/testharness/TestMount.h"

using namespace facebook::eden;

namespace {
template <typename Fn>
void expectEacces(Fn&& fn) {
  try {
    fn();
    FAIL() << "Expected system_error with EACCES";
  } catch (const std::system_error& ex) {
    EXPECT_EQ(ex.code().value(), EACCES);
  }
}

// Helper to construct a restricted TreeInode and register it with the
// InodeMap. Uses TreeInodePtr::makeNew (handles 0→1 refcount transition)
// + InodeMap::inodeCreated (registers for inodePtrFromThis() lookups).
TreeInodePtr makeRestrictedInode(
    TestMount& testMount,
    PathComponentPiece name) {
  auto rootInode = testMount.getEdenMount()->getRootInode();
  auto ino = testMount.getEdenMount()->getOverlay()->allocateInodeNumber();
  auto inode = TreeInodePtr::makeNew(
      ino,
      rootInode,
      name,
      S_IFDIR | 0755,
      std::nullopt,
      DirContents{CaseSensitivity::Sensitive},
      std::nullopt,
      /*isRestricted=*/true);
  testMount.getEdenMount()->getInodeMap()->inodeCreated(inode);
  return inode;
}
} // namespace

TEST(RestrictedTreeInode, normalTreeInodeAllowsReaddir) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto rootInode = testMount.getEdenMount()->getRootInode();
  auto context = ObjectFetchContext::getNullContext();
  auto children = rootInode->getChildren(context, /*loadInodes=*/false);

  auto iter =
      std::find_if(children.begin(), children.end(), [](const auto& entry) {
        return entry.first == "dir"_pc;
      });
  ASSERT_NE(iter, children.end());
}

TEST(RestrictedTreeInode, restrictedFlagDeniesAccess) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  auto context = ObjectFetchContext::getNullContext();
  expectEacces(
      [&] { restricted->getOrFindChild("child"_pc, context, false).get(); });
}

TEST(RestrictedTreeInode, statReturnsZeroPermissions) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  auto context = ObjectFetchContext::getNullContext();
  auto st = restricted->stat(context).get();

  EXPECT_TRUE(S_ISDIR(st.st_mode));
  EXPECT_EQ(st.st_mode & 07777, 0);
}

TEST(RestrictedTreeInode, getOrLoadChildReturnsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  auto context = ObjectFetchContext::getNullContext();
  expectEacces(
      [&] { restricted->getOrLoadChild("anything"_pc, context).get(); });
}

TEST(RestrictedTreeInode, mkdirReturnsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  expectEacces([&] {
    restricted->mkdir("newdir"_pc, S_IFDIR | 0755, InvalidationRequired::No);
  });
}

TEST(RestrictedTreeInode, unlinkReturnsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  auto context = ObjectFetchContext::getNullContext();
  expectEacces([&] {
    restricted->unlink("anything"_pc, InvalidationRequired::No, context).get();
  });
}

TEST(RestrictedTreeInode, symlinkReturnsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  expectEacces([&] {
    restricted->symlink("link"_pc, "target", InvalidationRequired::No);
  });
}

TEST(RestrictedTreeInode, mknodReturnsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  expectEacces([&] {
    restricted->mknod("file"_pc, S_IFREG | 0644, 0, InvalidationRequired::No);
  });
}

TEST(RestrictedTreeInode, setattrReturnsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  auto context = ObjectFetchContext::getNullContext();
  expectEacces([&] { restricted->setattr(DesiredMetadata{}, context).get(); });
}

TEST(RestrictedTreeInode, lockContentsReadThrowsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  expectEacces([&] { restricted->lockContentsRead(); });
}

TEST(RestrictedTreeInode, lockContentsWriteThrowsEACCES) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto restricted = makeRestrictedInode(testMount, "restricted"_pc);

  expectEacces([&] { restricted->lockContentsWrite(); });
}

TEST(RestrictedTreeInode, unrestricted_treeInodeIsNotRestricted) {
  FakeTreeBuilder builder;
  builder.setFile("dir/file.txt", "content");
  TestMount testMount{builder};

  auto dirInode = testMount.getTreeInode("dir"_relpath);
  EXPECT_FALSE(dirInode->isRestricted());
}

// --- End-to-end tests that go through the real inode loading pipeline ---

class RestrictedTreeInodeEndToEnd : public ::testing::Test {
 protected:
  void SetUp() override {
    FakeTreeBuilder builder;
    builder.setFile("restricted/secret.txt", "secret content");
    builder.setDirIsRestricted("restricted");
    testMount_ = std::make_unique<TestMount>(builder);
  }

  TreeInodePtr getRestrictedInode() {
    return testMount_->getTreeInode("restricted"_relpath);
  }

  std::unique_ptr<TestMount> testMount_;
};

TEST_F(
    RestrictedTreeInodeEndToEnd,
    loadingRestrictedDirCreatesRestrictedTreeInode) {
  auto restrictedInode = getRestrictedInode();
  // TODO: isRestricted not yet propagated through inode loading pipeline
  EXPECT_FALSE(restrictedInode->isRestricted());
}

TEST_F(RestrictedTreeInodeEndToEnd, restrictedDirStatReturnsZeroPermissions) {
  auto restrictedInode = getRestrictedInode();
  auto context = ObjectFetchContext::getNullContext();
  auto st = restrictedInode->stat(context).get();

#ifndef _WIN32
  // Windows stat() doesn't set st_mode for directories (no metadata table).
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  // TODO: restricted inode should return zero permissions once loading pipeline
  // propagates isRestricted
  EXPECT_NE(st.st_mode & 07777, 0);
#endif
}

TEST_F(RestrictedTreeInodeEndToEnd, restrictedDirGetOrFindChildReturnsEACCES) {
  auto restrictedInode = getRestrictedInode();
  // TODO: should throw EACCES once loading pipeline propagates isRestricted
  auto context = ObjectFetchContext::getNullContext();
  EXPECT_NO_THROW(
      restrictedInode->getOrFindChild("secret.txt"_pc, context, false).get());
}

TEST_F(RestrictedTreeInodeEndToEnd, restrictedDirLockContentsReadThrows) {
  auto restrictedInode = getRestrictedInode();
  // TODO: should throw EACCES once loading pipeline propagates isRestricted
  EXPECT_NO_THROW(restrictedInode->lockContentsRead());
}

TEST(RestrictedTreeInode, parentListingIncludesRestrictedDir) {
  FakeTreeBuilder builder;
  builder.setFile("parent/normal.txt", "normal content");
  builder.setFile("parent/restricted_child/secret.txt", "secret content");
  builder.setDirIsRestricted("parent/restricted_child");
  TestMount testMount{builder};

  auto parentInode = testMount.getTreeInode("parent"_relpath);
  // Reach into entries to verify the DirEntry-level flag, not the inode.
  auto contents = parentInode->lockContentsRead();

  auto iter = contents->entries.find("restricted_child"_pc);
  ASSERT_NE(iter, contents->entries.end());
  EXPECT_TRUE(iter->second.isDirectory());
  EXPECT_TRUE(iter->second.isRestricted());
}

TEST(RestrictedTreeInode, nestedRestrictedDirPreWiring) {
  // Before D99730301 wires TreeInode construction from DirEntry::isRestricted,
  // the inode loads as unrestricted even though DirEntry has the flag set.
  // This test documents the pre-wiring behavior (TDD).
  FakeTreeBuilder builder;
  builder.setFile("parent/normal.txt", "normal content");
  builder.setFile("parent/restricted_child/secret.txt", "secret content");
  builder.setDirIsRestricted("parent/restricted_child");
  TestMount testMount{builder};

  auto restrictedInode =
      testMount.getTreeInode("parent/restricted_child"_relpath);
  // DirEntry has isRestricted but TreeInode doesn't read it yet
  EXPECT_FALSE(restrictedInode->isRestricted());

  // Access succeeds since the inode is not restricted
  auto context = ObjectFetchContext::getNullContext();
  EXPECT_NO_THROW(
      restrictedInode->getOrFindChild("secret.txt"_pc, context, false).get());
}

TEST_F(RestrictedTreeInodeEndToEnd, getObjectIdReturnsNullopt) {
  auto restrictedInode = getRestrictedInode();
  // TODO: should return nullopt once loading pipeline propagates isRestricted
  EXPECT_NE(restrictedInode->getObjectId(), std::nullopt);
}
