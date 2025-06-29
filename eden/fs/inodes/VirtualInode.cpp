/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include "eden/fs/inodes/VirtualInode.h"

#include "eden/common/utils/Match.h"
#include "eden/common/utils/StatTimes.h"
#include "eden/fs/inodes/FileInode.h"
#include "eden/fs/inodes/InodeError.h"
#include "eden/fs/inodes/TreeInode.h"
#include "eden/fs/model/Tree.h"
#include "eden/fs/model/TreeAuxData.h"
#include "eden/fs/service/gen-cpp2/eden_types.h"
#include "eden/fs/store/ObjectStore.h"
#include "eden/fs/utils/EdenError.h"

namespace facebook::eden {

InodePtr VirtualInode::asInodePtr() const {
  return std::get<InodePtr>(variant_);
}

// Helper template for std::visit calls below
template <class>
inline constexpr bool always_false_v = false;

dtype_t VirtualInode::getDtype() const {
  return match(
      variant_,
      [](const InodePtr& inode) { return inode->getType(); },
      [](const UnmaterializedUnloadedBlobDirEntry& entry) {
        return entry.getDtype();
      },
      [](const TreePtr&) { return dtype_t::Dir; },
      [](const TreeEntry& entry) { return entry.getDtype(); });
}

bool VirtualInode::isDirectory() const {
  return getDtype() == dtype_t::Dir;
}

std::optional<ObjectId> VirtualInode::getObjectId() const {
  return match(
      variant_,
      [](const InodePtr& inode) { return inode->getObjectId(); },
      [](const TreePtr& tree) -> std::optional<ObjectId> {
        return tree->getHash();
      },
      [](const auto& entry) -> std::optional<ObjectId> {
        return entry.getObjectId();
      });
}

VirtualInode::ContainedType VirtualInode::testGetContainedType() const {
  return match(
      variant_,
      [](const InodePtr&) { return ContainedType::Inode; },
      [](const UnmaterializedUnloadedBlobDirEntry&) {
        return ContainedType::DirEntry;
      },
      [](const TreePtr&) { return ContainedType::Tree; },
      [](const TreeEntry&) { return ContainedType::TreeEntry; });
}

ImmediateFuture<Hash32> VirtualInode::getBlake3(
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  // Ensure this is a regular file.
  // We intentionally want to refuse to compute the blake3 of symlinks
  switch (filteredEntryDtype(
      getDtype(), objectStore->getWindowsSymlinksEnabled())) {
    case dtype_t::Dir:
      return makeImmediateFuture<Hash32>(PathError(EISDIR, path));
    case dtype_t::Symlink:
      return makeImmediateFuture<Hash32>(
          PathError(EINVAL, path, "file is a symlink"));
    case dtype_t::Regular:
      break;
    default:
      return makeImmediateFuture<Hash32>(
          PathError(EINVAL, path, "variant is of unhandled type"));
  }

  // This is now guaranteed to be a dtype_t::Regular file. This means there's no
  // need for a Tree case, as Trees are always directories.

  return match(
      variant_,
      [&](const InodePtr& inode) {
        return inode.asFilePtr()->getBlake3(fetchContext);
      },
      [&](const UnmaterializedUnloadedBlobDirEntry& entry) {
        return objectStore->getBlobBlake3(entry.getObjectId(), fetchContext);
      },
      [&](const TreePtr&) {
        return makeImmediateFuture<Hash32>(PathError(EISDIR, path));
      },
      [&](const TreeEntry& entry) {
        const auto& hash = entry.getContentBlake3();
        // If available, use the TreeEntry's ContentsSha1
        if (hash.has_value()) {
          return ImmediateFuture<Hash32>(hash.value());
        }
        // Revert to querying the objectStore for the file's metadata
        return objectStore->getBlobBlake3(entry.getHash(), fetchContext);
      });
}

ImmediateFuture<Hash32> VirtualInode::getDigestHash(
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  // Ensure this is a regular file or directory.
  // We intentionally want to refuse to compute the digestHash of symlinks
  switch (filteredEntryDtype(
      getDtype(), objectStore->getWindowsSymlinksEnabled())) {
    case dtype_t::Symlink:
      return makeImmediateFuture<Hash32>(
          PathError(EINVAL, path, "file is a symlink"));
    case dtype_t::Dir:
      break;
    case dtype_t::Regular:
      // The DigestHash of a file is the same as the Blake3 hash for that file
      return getBlake3(path, objectStore, fetchContext);
    default:
      return makeImmediateFuture<Hash32>(
          PathError(EINVAL, path, "variant is of unhandled type"));
  }

  // This is now guaranteed to be a dtype_t::Dir. This means there's no
  // need to handle any file case

  return match(
      variant_,
      [&](const InodePtr& inode) {
        auto treeFut = inode.asTreePtr()->getDigestHash(fetchContext);
        return std::move(treeFut).thenValue(
            [treePath = path.copy()](std::optional<Hash32> hash) {
              if (hash.has_value()) {
                return ImmediateFuture<Hash32>{hash.value()};
              } else {
                return makeImmediateFuture<Hash32>(newEdenError(
                    EINVAL,
                    EdenErrorType::GENERIC_ERROR,
                    fmt::format("digest hash missing for tree: {}", treePath)));
              }
            });
      },
      [&](const UnmaterializedUnloadedBlobDirEntry& entry) {
        return objectStore->getTreeDigestHash(
            entry.getObjectId(), fetchContext);
      },
      [&](const TreePtr& tree) {
        return objectStore->getTreeDigestHash(tree->getHash(), fetchContext);
      },
      [&](const TreeEntry& entry) {
        return objectStore->getTreeDigestHash(entry.getHash(), fetchContext);
      });
}

ImmediateFuture<Hash20> VirtualInode::getSHA1(
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  // Ensure this is a regular file.
  // We intentionally want to refuse to compute the SHA1 of symlinks
  switch (filteredEntryDtype(
      getDtype(), objectStore->getWindowsSymlinksEnabled())) {
    case dtype_t::Dir:
      return makeImmediateFuture<Hash20>(PathError(EISDIR, path));
    case dtype_t::Symlink:
      return makeImmediateFuture<Hash20>(
          PathError(EINVAL, path, "file is a symlink"));
    case dtype_t::Regular:
      break;
    default:
      return makeImmediateFuture<Hash20>(
          PathError(EINVAL, path, "variant is of unhandled type"));
  }

  // This is now guaranteed to be a dtype_t::Regular file. This means there's no
  // need for a Tree case, as Trees are always directories.

  return match(
      variant_,
      [&](const InodePtr& inode) {
        return inode.asFilePtr()->getSha1(fetchContext);
      },
      [&](const UnmaterializedUnloadedBlobDirEntry& entry) {
        return objectStore->getBlobSha1(entry.getObjectId(), fetchContext);
      },
      [&](const TreePtr&) {
        return makeImmediateFuture<Hash20>(PathError(EISDIR, path));
      },
      [&](const TreeEntry& entry) {
        const auto& hash = entry.getContentSha1();
        // If available, use the TreeEntry's ContentsSha1
        if (hash.has_value()) {
          return ImmediateFuture<Hash20>(hash.value());
        }
        // Revert to querying the objectStore for the file's metadata
        return objectStore->getBlobSha1(entry.getHash(), fetchContext);
      });
}

ImmediateFuture<std::optional<TreeEntryType>> VirtualInode::getTreeEntryType(
    RelativePathPiece path,
    const ObjectFetchContextPtr& fetchContext,
    bool windowsSymlinksEnabled) const {
  using R = ImmediateFuture<std::optional<TreeEntryType>>;
  return match(
      variant_,
      [&](const InodePtr& inode) -> R {
#ifdef _WIN32
        (void)fetchContext;
        // stat does not have real data for an inode on Windows, so we can not
        // directly use the mode bits. Further inodes are only tree or regular
        // files on windows see treeEntryTypeFromMode.
        switch (inode->getType()) {
          case dtype_t::Dir:
            return TreeEntryType::TREE;
          case dtype_t::Regular:
            return TreeEntryType::REGULAR_FILE;
          case dtype_t::Symlink:
            return windowsSymlinksEnabled ? TreeEntryType::SYMLINK
                                          : TreeEntryType::REGULAR_FILE;
          default:
            return std::nullopt;
        }
#else
        (void)path;
        return inode->stat(fetchContext).thenValue([](const struct stat&& st) {
          return treeEntryTypeFromMode(st.st_mode);
        });
#endif
      },
      [&](const UnmaterializedUnloadedBlobDirEntry& entry) {
        return makeImmediateFutureWith([mode = entry.getInitialMode()]() {
          return treeEntryTypeFromMode(mode);
        });
      },
      [&](const TreePtr&) -> R { return TreeEntryType::TREE; },
      [&](const TreeEntry& entry) -> R {
        return filteredEntryType(entry.getType(), windowsSymlinksEnabled);
      });
}

ImmediateFuture<BlobAuxData> VirtualInode::getBlobAuxData(
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext,
    bool blake3Required) const {
  return match(
      variant_,
      [&](const InodePtr& inode) {
        return inode.asFilePtr()->getBlobAuxData(fetchContext, blake3Required);
      },
      [&](const TreePtr&) {
        return makeImmediateFuture<BlobAuxData>(PathError(EISDIR, path));
      },
      [&](auto& entry) {
        return objectStore->getBlobAuxData(
            entry.getObjectId(), fetchContext, blake3Required);
      });
}

ImmediateFuture<TreeAuxData> VirtualInode::getTreeAuxData(
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  return match(
      variant_,
      [&](const InodePtr& inode) {
        return inode.asTreePtr()
            ->getTreeAuxData(fetchContext)
            .thenValue([path](std::optional<TreeAuxData> treeAux) {
              if (treeAux.has_value()) {
                return ImmediateFuture<TreeAuxData>(treeAux.value());
              } else {
                return makeImmediateFuture<TreeAuxData>(newEdenError(
                    EINVAL,
                    EdenErrorType::GENERIC_ERROR,
                    fmt::format("tree aux data missing for tree: {}", path)));
              }
            });
      },
      [&](const TreePtr& tree) {
        return objectStore->getTreeAuxData(tree->getHash(), fetchContext);
      },
      [&](auto& entry) {
        return objectStore->getTreeAuxData(entry.getObjectId(), fetchContext);
      });
}

ImmediateFuture<EntryAttributes> VirtualInode::getEntryAttributesForNonFile(
    EntryAttributeFlags requestedAttributes,
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext,
    std::optional<TreeEntryType> entryType,
    int errorCode,
    std::string additionalErrorContext) const {
  std::optional<folly::Try<Hash20>> sha1;
  if (requestedAttributes.contains(ENTRY_ATTRIBUTE_SHA1)) {
    sha1 =
        folly::Try<Hash20>{PathError{errorCode, path, additionalErrorContext}};
  }

  std::optional<folly::Try<std::optional<TreeEntryType>>> type;
  if (requestedAttributes.contains(ENTRY_ATTRIBUTE_SOURCE_CONTROL_TYPE)) {
    type = folly::Try<std::optional<TreeEntryType>>{entryType};
  }

  std::optional<folly::Try<std::optional<ObjectId>>> objectId;
  auto oid = getObjectId();
  if (requestedAttributes.contains(ENTRY_ATTRIBUTE_OBJECT_ID)) {
    objectId = folly::Try<std::optional<ObjectId>>{oid};
  }

  std::optional<folly::Try<uint64_t>> size;
  if (requestedAttributes.contains(ENTRY_ATTRIBUTE_SIZE)) {
    size = folly::Try<uint64_t>{
        PathError{errorCode, path, additionalErrorContext}};
  }

  std::optional<folly::Try<Hash32>> blake3;
  if (requestedAttributes.contains(ENTRY_ATTRIBUTE_BLAKE3)) {
    blake3 =
        folly::Try<Hash32>{PathError{errorCode, path, additionalErrorContext}};
  }

  std::optional<folly::Try<Hash32>> digestHash;
  std::optional<folly::Try<uint64_t>> digestSize;

  // The entry is a symlink, socket, or other unsupported type. We return
  // error values for these entry types if they were requested.
  //
  // entryType is std::nullopt if the entry is a socket or other non-scm type
  if (entryType.value_or(TreeEntryType::SYMLINK) != TreeEntryType::TREE) {
    if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_SIZE)) {
      digestSize = folly::Try<uint64_t>{
          PathError{errorCode, path, additionalErrorContext}};
    }

    if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_HASH)) {
      digestHash = folly::Try<Hash32>{
          PathError{errorCode, path, std::move(additionalErrorContext)}};
    }
  } else {
    // The entry is a tree, and therefore we can attempt to compute tree
    // aux data for it. However, we can only compute the additional attributes
    // of trees that have ObjectIds. In other words, the tree must be
    // unmaterialized.
    if ((requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_HASH) ||
         requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_SIZE)) &&
        oid.has_value()) {
      auto treeAuxFut =
          objectStore->getTreeAuxData(oid.value(), fetchContext)
              .thenValue([requestedAttributes,
                          sha1,
                          type,
                          objectId,
                          blake3,
                          size,
                          digestSize,
                          digestHash](TreeAuxData treeAux) mutable {
                if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_HASH)) {
                  digestHash =
                      std::optional<folly::Try<Hash32>>{treeAux.digestHash};
                }
                if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_SIZE)) {
                  digestSize = std::optional<folly::Try<uint64_t>>{
                      std::move(treeAux.digestSize)};
                }
                return EntryAttributes{
                    std::move(sha1),
                    std::move(blake3),
                    std::move(size),
                    std::move(type),
                    std::move(objectId),
                    std::move(digestSize),
                    std::move(digestHash)};
              });
      return std::move(treeAuxFut)
          .thenError([requestedAttributes,
                      treeSha1 = std::move(sha1),
                      treeType = std::move(type),
                      treeObjectId = std::move(objectId),
                      treeBlake3 = std::move(blake3),
                      treeSize = std::move(size),
                      treeDigestSize = std::move(digestSize),
                      treeDigestHash = std::move(digestHash)](
                         const folly::exception_wrapper& ex) mutable {
            // We failed to get tree aux data. This shouldn't cause the
            // entire result to be an error. We can return whichever
            // attributes we successfully fetched.
            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_HASH)) {
              treeDigestHash = folly::Try<Hash32>{ex};
            }

            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_SIZE)) {
              treeDigestSize = folly::Try<uint64_t>{ex};
            }

            return EntryAttributes{
                std::move(treeSha1),
                std::move(treeBlake3),
                std::move(treeSize),
                std::move(treeType),
                std::move(treeObjectId),
                std::move(treeDigestSize),
                std::move(treeDigestHash)};
          });
    }
    // We return empty tree aux data attributes for materialized directories
  }

  return EntryAttributes{
      std::move(sha1),
      std::move(blake3),
      std::move(size),
      std::move(type),
      std::move(objectId),
      std::move(digestSize),
      std::move(digestHash)};
}

ImmediateFuture<EntryAttributes> VirtualInode::getEntryAttributes(
    EntryAttributeFlags requestedAttributes,
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  bool windowsSymlinksEnabled = objectStore->getWindowsSymlinksEnabled();
  // For non regular files we return errors for hashes and sizes.
  // We intentionally want to refuse to compute the SHA1 of symlinks.
  auto dtype = filteredEntryDtype(getDtype(), windowsSymlinksEnabled);
  switch (dtype) {
    case dtype_t::Regular:
      break;
    case dtype_t::Dir:
      return getEntryAttributesForNonFile(
          requestedAttributes,
          path,
          objectStore,
          fetchContext,
          TreeEntryType::TREE,
          EISDIR,
          {});
    case dtype_t::Symlink:
      return getEntryAttributesForNonFile(
          requestedAttributes,
          path,
          objectStore,
          fetchContext,
          TreeEntryType::SYMLINK,
          EINVAL,
          "file is a symlink");
    default:
      return getEntryAttributesForNonFile(
          requestedAttributes,
          path,
          objectStore,
          fetchContext,
          std::nullopt,
          EINVAL,
          fmt::format(
              "file is a non-source-control type: {}",
              folly::to_underlying(dtype)));
  }
  // This is now guaranteed to be a dtype_t::Regular file. This
  // means there's no need for a Tree case, as Trees are always
  // directories. It's included to check that the visitor here is
  // exhaustive.
  auto entryTypeFuture = ImmediateFuture<std::optional<TreeEntryType>>{
      PathError{EINVAL, path, "type not requested"}};
  if (requestedAttributes.contains(ENTRY_ATTRIBUTE_SOURCE_CONTROL_TYPE)) {
    entryTypeFuture =
        getTreeEntryType(path, fetchContext, windowsSymlinksEnabled);
  }
  auto blobAuxdataFuture = ImmediateFuture<BlobAuxData>{
      PathError{EINVAL, path, "neither sha1 nor size requested"}};
  // sha1, blake3 and size come together so, there isn't much point of splitting
  // them up
  if (requestedAttributes.containsAnyOf(
          ENTRY_ATTRIBUTE_SIZE | ENTRY_ATTRIBUTE_SHA1 | ENTRY_ATTRIBUTE_BLAKE3 |
          ENTRY_ATTRIBUTE_DIGEST_SIZE | ENTRY_ATTRIBUTE_DIGEST_HASH)) {
    blobAuxdataFuture = getBlobAuxData(
        path,
        objectStore,
        fetchContext,
        requestedAttributes.containsAnyOf(
            ENTRY_ATTRIBUTE_BLAKE3 | ENTRY_ATTRIBUTE_DIGEST_HASH));
  }

  std::optional<ObjectId> objectId;
  if (requestedAttributes.contains(ENTRY_ATTRIBUTE_OBJECT_ID)) {
    objectId = getObjectId();
  }

  return collectAll(std::move(entryTypeFuture), std::move(blobAuxdataFuture))
      .thenValue(
          [requestedAttributes,
           entryObjectId = std::move(objectId),
           filePath = RelativePath{path}](
              std::tuple<
                  folly::Try<std::optional<TreeEntryType>>,
                  folly::Try<BlobAuxData>> rawAttributeData) mutable
          -> EntryAttributes {
            auto& [entryType, blobAuxdata] = rawAttributeData;

            std::optional<folly::Try<Hash20>> sha1;
            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_SHA1)) {
              sha1 = blobAuxdata.hasException()
                  ? folly::Try<Hash20>(blobAuxdata.exception())
                  : folly::Try<Hash20>(blobAuxdata.value().sha1);
            }

            std::optional<folly::Try<Hash32>> blake3;
            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_BLAKE3)) {
              if (blobAuxdata.hasException()) {
                blake3 = folly::Try<Hash32>(blobAuxdata.exception());
              } else {
                blake3 = blobAuxdata.value().blake3
                    ? folly::Try<Hash32>(blobAuxdata.value().blake3.value())
                    : folly::Try<Hash32>(
                          folly::make_exception_wrapper<std::runtime_error>(
                              "no blake3 available"));
              }
            }

            std::optional<folly::Try<uint64_t>> size;
            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_SIZE)) {
              size = blobAuxdata.hasException()
                  ? folly::Try<uint64_t>(blobAuxdata.exception())
                  : folly::Try<uint64_t>(blobAuxdata.value().size);
            }

            std::optional<folly::Try<std::optional<TreeEntryType>>> type;
            if (requestedAttributes.contains(
                    ENTRY_ATTRIBUTE_SOURCE_CONTROL_TYPE)) {
              type = std::move(entryType);
            }

            std::optional<folly::Try<std::optional<ObjectId>>> objectId;
            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_OBJECT_ID)) {
              objectId =
                  folly::Try<std::optional<ObjectId>>{std::move(entryObjectId)};
            }

            std::optional<folly::Try<uint64_t>> digestSize;
            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_SIZE)) {
              digestSize = blobAuxdata.hasException()
                  ? folly::Try<uint64_t>(blobAuxdata.exception())
                  : folly::Try<uint64_t>(blobAuxdata.value().size);
            }

            std::optional<folly::Try<Hash32>> digestHash;
            if (requestedAttributes.contains(ENTRY_ATTRIBUTE_DIGEST_HASH)) {
              if (blobAuxdata.hasException()) {
                digestHash = folly::Try<Hash32>(blobAuxdata.exception());
              } else {
                digestHash = blobAuxdata.value().blake3
                    ? folly::Try<Hash32>(blobAuxdata.value().blake3.value())
                    : folly::Try<Hash32>(
                          folly::make_exception_wrapper<std::runtime_error>(
                              "no blake3 available"));
              }
            }

            return EntryAttributes{
                std::move(sha1),
                std::move(blake3),
                std::move(size),
                std::move(type),
                std::move(objectId),
                std::move(digestSize),
                std::move(digestHash)};
          });
}

// Returns a subset of `struct stat` required by
// EdenServiceHandler::semifuture_getFileInformation()
ImmediateFuture<struct stat> VirtualInode::stat(
    // TODO: can lastCheckoutTime be fetched from some global edenMount()?
    //
    // VirtualInode is used to traverse the tree. However, the global
    // renameLock is NOT held during these traversals, so we're not protected
    // from nodes/trees being moved around during the traversal.
    //
    // It's inconvenient to pass the lastCheckoutTime in from the caller, but we
    // got to this particular location in the mount by starting at a particular
    // root node with that checkout time. Because we don't hold the rename lock,
    // it's not clear if the current global edenMount object's lastCheckoutTime
    // is any more or less correct than the passed in lastCheckoutTime. It's
    // _probably_ safer to use the older one, as that represents what the state
    // of the repository WAS when the traversal started. If we queried the
    // global eden mount here for the lastCheckoutTime, we may get a time in the
    // future when one of our parents changed, and we may be mis-reporting the
    // state of the tree.
    //
    // In short: there's a potential race condition here that may cause
    // mis-reporting.
    const struct timespec& lastCheckoutTime,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  return std::visit(
      [&](auto&& arg) -> ImmediateFuture<struct stat> {
        using T = std::decay_t<decltype(arg)>;
        ObjectId objectId;
        mode_t mode;
        if constexpr (std::is_same_v<T, InodePtr>) {
          // Note: there's no need to modify the return value of stat here, as
          // the inode implementations are what all the other cases are trying
          // to emulate.
          return arg->stat(fetchContext);
        } else if constexpr (std::is_same_v<
                                 T,
                                 UnmaterializedUnloadedBlobDirEntry>) {
          objectId = arg.getObjectId();
          mode = arg.getInitialMode();
          // fallthrough
        } else if constexpr (std::is_same_v<T, TreePtr>) {
          struct stat st = {};
          st.st_mode = static_cast<decltype(st.st_mode)>(treeMode_);
          stMtime(st, lastCheckoutTime);
#ifdef _WIN32
          // Windows returns zero for st_mode and mtime
          st.st_mode = static_cast<decltype(st.st_mode)>(0);
          {
            struct timespec ts0 {};
            stMtime(st, ts0);
          }
#endif
          st.st_size = 0U;
          return st;
        } else if constexpr (std::is_same_v<T, TreeEntry>) {
          objectId = arg.getHash();
          mode = modeFromTreeEntryType(filteredEntryType(
              arg.getType(), objectStore->getWindowsSymlinksEnabled()));
          // fallthrough
        } else {
          static_assert(always_false_v<T>, "non-exhaustive visitor!");
        }
        return objectStore->getBlobAuxData(objectId, fetchContext)
            .thenValue([mode, lastCheckoutTime](const BlobAuxData& auxData) {
              struct stat st = {};
              st.st_mode = static_cast<decltype(st.st_mode)>(mode);
              stMtime(st, lastCheckoutTime);
#ifdef _WIN32
              // Windows returns zero for st_mode and mtime
              st.st_mode = static_cast<decltype(st.st_mode)>(0);
              {
                struct timespec ts0 {};
                stMtime(st, ts0);
              }
#endif
              st.st_size = static_cast<decltype(st.st_size)>(auxData.size);
              return st;
            });
      },
      variant_);
}

namespace {
/**
 * Helper function for getChildren when the current node is a Tree.
 */
std::vector<std::pair<PathComponent, ImmediateFuture<VirtualInode>>>
getChildrenHelper(
    const TreePtr& tree,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) {
  std::vector<std::pair<PathComponent, ImmediateFuture<VirtualInode>>> result{};
  result.reserve(tree->size());

  for (auto& child : *tree) {
    const auto* treeEntry = &child.second;
    if (treeEntry->isTree()) {
      result.emplace_back(
          child.first,
          objectStore->getTree(treeEntry->getHash(), fetchContext)
              .thenValue([mode = modeFromTreeEntryType(treeEntry->getType())](
                             TreePtr tree) {
                return VirtualInode{std::move(tree), mode};
              }));
    } else {
      // This is a file, return the TreeEntry for it
      result.emplace_back(child.first, VirtualInode{*treeEntry});
    }
  }

  return result;
}
} // namespace

folly::Try<std::vector<std::pair<PathComponent, ImmediateFuture<VirtualInode>>>>
VirtualInode::getChildren(
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) {
  if (!isDirectory()) {
    return folly::Try<
        std::vector<std::pair<PathComponent, ImmediateFuture<VirtualInode>>>>(
        PathError(ENOTDIR, path));
  }

  auto notDirectory = [&] {
    // These represent files in VirtualInode, and can't be descended
    return folly::Try<
        std::vector<std::pair<PathComponent, ImmediateFuture<VirtualInode>>>>{
        PathError(ENOTDIR, path, "variant is of unhandled type")};
  };

  return match(
      variant_,
      [&](const InodePtr& inode) {
        return folly::Try<std::vector<
            std::pair<PathComponent, ImmediateFuture<VirtualInode>>>>{
            inode.asTreePtr()->getChildren(fetchContext, false)};
      },
      [&](const TreePtr& tree) {
        return folly::Try<std::vector<
            std::pair<PathComponent, ImmediateFuture<VirtualInode>>>>{
            getChildrenHelper(tree, objectStore, fetchContext)};
      },
      [&](const UnmaterializedUnloadedBlobDirEntry&) { return notDirectory(); },
      [&](const TreeEntry&) { return notDirectory(); });
}

ImmediateFuture<
    std::vector<std::pair<PathComponent, folly::Try<EntryAttributes>>>>
VirtualInode::getChildrenAttributes(
    EntryAttributeFlags requestedAttributes,
    RelativePath path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) {
  auto children = this->getChildren(path.piece(), objectStore, fetchContext);

  if (children.hasException()) {
    return ImmediateFuture<
        std::vector<std::pair<PathComponent, folly::Try<EntryAttributes>>>>{
        children.exception()};
  }

  std::vector<PathComponent> names{};
  std::vector<ImmediateFuture<EntryAttributes>> attributesFutures{};

  names.reserve(children.value().size());
  attributesFutures.reserve(children.value().size());

  for (auto& nameAndvirtualInode : children.value()) {
    names.push_back(nameAndvirtualInode.first);
    attributesFutures.push_back(
        std::move(nameAndvirtualInode.second)
            .thenValue([requestedAttributes,
                        subPath = path + nameAndvirtualInode.first,
                        objectStore,
                        fetchContext =
                            fetchContext.copy()](VirtualInode virtualInode) {
              return virtualInode.getEntryAttributes(
                  requestedAttributes, subPath, objectStore, fetchContext);
            }));
  }
  return collectAll(std::move(attributesFutures))
      .thenValue(
          [names = std::move(names)](
              std::vector<folly::Try<EntryAttributes>> attributes) mutable {
            std::vector<std::pair<PathComponent, folly::Try<EntryAttributes>>>
                zippedResult{};
            zippedResult.reserve(attributes.size());
            XDCHECK_EQ(attributes.size(), names.size())
                << "Missing/too many attributes for the names.";
            for (uint32_t i = 0; i < attributes.size(); ++i) {
              zippedResult.emplace_back(
                  std::move(names.at(i)), std::move(attributes.at(i)));
            }
            return zippedResult;
          });
}

namespace {
/**
 * Helper function for getOrFindChild when the current node is a Tree.
 */
ImmediateFuture<VirtualInode> getOrFindChildHelper(
    TreePtr tree,
    PathComponentPiece childName,
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) {
  // Lookup the next child
  const auto it = tree->find(childName);
  if (it == tree->cend()) {
    // Note that the path printed below is the requested path that is being
    // walked, childName may appear anywhere in the path.
    XLOG(DBG7) << "attempted to find non-existent TreeEntry \"" << childName
               << "\" in " << path;
    return makeImmediateFuture<VirtualInode>(
        std::system_error(ENOENT, std::generic_category()));
  }

  // Always descend if the treeEntry is a Tree
  const auto* treeEntry = &it->second;
  if (treeEntry->isTree()) {
    return objectStore->getTree(treeEntry->getHash(), fetchContext)
        .thenValue(
            [mode = modeFromTreeEntryType(treeEntry->getType())](TreePtr tree) {
              return VirtualInode{std::move(tree), mode};
            });
  } else {
    // This is a file, return the TreeEntry for it
    return VirtualInode{*treeEntry};
  }
}
} // namespace

ImmediateFuture<VirtualInode> VirtualInode::getOrFindChild(
    PathComponentPiece childName,
    RelativePathPiece path,
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  if (!isDirectory()) {
    return makeImmediateFuture<VirtualInode>(PathError(ENOTDIR, path));
  }
  auto notDirectory = [&] {
    // These represent files in VirtualInode, and can't be descended
    return makeImmediateFuture<VirtualInode>(
        PathError(ENOTDIR, path, "variant is of unhandled type"));
  };
  return match(
      variant_,
      [&](const InodePtr& inode) {
        return inode.asTreePtr()->getOrFindChild(
            childName, fetchContext, false);
      },
      [&](const TreePtr& tree) {
        return getOrFindChildHelper(
            tree, childName, path, objectStore, fetchContext);
      },
      [&](const UnmaterializedUnloadedBlobDirEntry&) { return notDirectory(); },
      [&](const TreeEntry&) { return notDirectory(); });
}

ImmediateFuture<std::string> VirtualInode::getBlob(
    const std::shared_ptr<ObjectStore>& objectStore,
    const ObjectFetchContextPtr& fetchContext) const {
  return match(
      variant_,
      [&](const InodePtr& inode) {
        auto content = inode.asFilePtr()->readAll(fetchContext);
        return ImmediateFuture<std::string>(std::move(content));
      },
      [&](const UnmaterializedUnloadedBlobDirEntry& entry) {
        const auto& objectId = entry.getObjectId();
        return objectStore->getBlob(objectId, fetchContext)
            .thenValue([](auto&& blob) { return blob->asString(); });
      },
      [&](const TreeEntry& treeEntry) {
        const auto& objectId = treeEntry.getObjectId();
        return objectStore->getBlob(objectId, fetchContext)
            .thenValue([](auto&& blob) { return blob->asString(); });
      },
      [&](const TreePtr&) {
        return makeImmediateFuture<std::string>(
            std::system_error(EISDIR, std::generic_category()));
      });
}

} // namespace facebook::eden
