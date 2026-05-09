#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2.

# pyre-strict

import abc
import configparser
import errno
import os
import stat
from typing import TYPE_CHECKING

from eden.integration.hg.lib.hg_extension_test_base import EdenHgTestCase, hg_test
from eden.integration.lib import hgrepo
from eden.integration.lib.eagerrepo import EagerRepo


class _RestrictedTreeTestBase(EdenHgTestCase, metaclass=abc.ABCMeta):
    """Base class for restricted tree tests using standard eagerepo setup."""

    initial_commit: str = ""
    swapped_commit: str = ""
    # Subclasses flip this to False to disable client-side enforcement.
    enable_restricted_tree_mode: bool = True
    # Subclasses flip this to True to enable server-side PermissionDenied.
    enable_server_acl_enforcement: bool = False

    def apply_hg_config_variant(self, hgrc: configparser.ConfigParser) -> None:
        super().apply_hg_config_variant(hgrc)
        # scmstore reads these from the backing repo's .hg/hgrc. EdenHgTestCase
        # writes this hgrc before eden.clone(), so the config is in place by
        # the time the backing store reads it.
        if self.enable_restricted_tree_mode:
            if not hgrc.has_section("experimental"):
                hgrc.add_section("experimental")
            hgrc["experimental"]["restricted-tree-mode"] = "enforced"
            # Companion: ACL data rides on tree child metadata, so without
            # tree-metadata-mode=always the acl_checker has nothing to enforce on.
            if not hgrc.has_section("scmstore"):
                hgrc.add_section("scmstore")
            hgrc["scmstore"]["tree-metadata-mode"] = "always"
        if not hgrc.has_section("slacl"):
            hgrc.add_section("slacl")
        # These settings apply only to the backing repo hgrc used by Sapling
        # commands in test setup, not the checked-out Eden client.
        hgrc["slacl"]["on-permission-denied"] = "warn"
        hgrc["slacl"]["server-acl-enforcement"] = (
            "true" if self.enable_server_acl_enforcement else "false"
        )

    def populate_backing_repo(self, repo: hgrepo.HgRepository) -> None:
        # Populate the eager backing repo directly so pulled trees carry the
        # ACL child metadata these tests are exercising. Committing in the
        # backing repo would go through a local-only path that bypasses it.
        eagerepo_path = repo.eagerepo
        assert eagerepo_path is not None, (
            "backing HgRepository.init() must populate self.eagerepo before "
            "populate_backing_repo runs"
        )
        eager = EagerRepo(
            eagerepo_path,
            hg_environment=repo.hg_environment,
            system_hgrc=None,
        )
        eager.init()

        # Initial commit: restricted/ has .slacl, regular/ does not.
        eager.write_file("regular/file.txt", "regular content")
        eager.write_file("restricted/.slacl", "acl config")
        eager.write_file("restricted/secret.txt", "secret content")
        eager.write_file("parent/normal_file.txt", "normal")
        eager.write_file("parent/nested_restricted/.slacl", "acl config")
        eager.write_file("parent/nested_restricted/deep.txt", "deep secret")
        eager.write_file("hello.txt", "hello")
        self.initial_commit = eager.commit("Initial commit.")

        # Swapped commit: restricted/ loses .slacl, regular/ gains it.
        eager.remove_file("restricted/.slacl")
        eager.write_file("regular/.slacl", "regular acl config")
        self.swapped_commit = eager.commit("Swap ACL state.")

        # Pull both commits into the backing repo via SLAPI. ``fetch_edenapi``
        # populates ``indexedlog_cache`` with entries that include
        # ``acl_children_indices`` derived from ``has_acl`` on children.
        # Pulling by hash avoids needing a server bookmark (``master`` is on
        # the disallowed list anyway).
        repo.hg("pull", "-r", self.initial_commit)
        repo.hg("pull", "-r", self.swapped_commit)
        repo.hg("update", self.initial_commit)


if TYPE_CHECKING:
    # At type-check time, pretend the mixin inherits from the test base so
    # Pyre can resolve self.assertRaises, self.mount, etc. without a flood
    # of type-ignore annotations. At runtime, the mixin stays a plain object
    # so the concrete subclasses' MRO (mixin + real base) is unchanged.
    _MethodsBase = _RestrictedTreeTestBase
else:
    _MethodsBase = object


class _RestrictedTreeTestMethods(_MethodsBase, metaclass=abc.ABCMeta):
    """Mixin with test methods parameterized by expect_restricted."""

    # Subclasses set this to False for config-off variants
    expect_restricted: bool = True

    def _assert_dir_blocked(self, path: str) -> None:
        """Assert directory is blocked (EACCES) or accessible, based on expect_restricted."""
        if self.expect_restricted:
            with self.assertRaises(OSError) as ctx:
                os.listdir(path)
            self.assertEqual(ctx.exception.errno, errno.EACCES)
        else:
            os.listdir(path)

    def _assert_file_blocked(self, path: str) -> None:
        """Assert file access is blocked or accessible."""
        if self.expect_restricted:
            with self.assertRaises(OSError) as ctx:
                with open(path, "r") as f:
                    f.read()
            self.assertEqual(ctx.exception.errno, errno.EACCES)
        else:
            with open(path, "r") as f:
                f.read()  # should not raise

    def test_regular_dir_is_accessible(self) -> None:
        """Regular directories should always be fully accessible."""
        entries = sorted(os.listdir(os.path.join(self.mount, "regular")))
        self.assertEqual(["file.txt"], entries)

        with open(os.path.join(self.mount, "regular", "file.txt"), "r") as f:
            self.assertEqual("regular content", f.read())

    def test_root_listing_includes_restricted_dir(self) -> None:
        """The root listing should include restricted directories."""
        entries = os.listdir(self.mount)
        self.assertIn("regular", entries)
        self.assertIn("restricted", entries)

    def test_regular_dir_stat_has_normal_permissions(self) -> None:
        st = os.lstat(os.path.join(self.mount, "regular"))
        self.assertTrue(stat.S_ISDIR(st.st_mode))
        self.assertNotEqual(st.st_mode & 0o7777, 0)


class _RestrictedTreeConfigOffBase(_RestrictedTreeTestBase, metaclass=abc.ABCMeta):
    """Base for tests with restricted tree mode disabled."""

    enable_restricted_tree_mode: bool = False


@hg_test
# pyre-ignore[13]: T62487924
class RestrictedTreeTest(_RestrictedTreeTestMethods, _RestrictedTreeTestBase):
    """Client-side enforcement via has_acl metadata."""

    pass


@hg_test
# pyre-ignore[13]: T62487924
class RestrictedTreeEnforcementTest(
    _RestrictedTreeTestMethods, _RestrictedTreeTestBase
):
    """Server-side enforcement via PermissionDenied."""

    enable_server_acl_enforcement: bool = True


@hg_test
# pyre-ignore[13]: T62487924
class RestrictedTreeConfigOffTest(
    _RestrictedTreeTestMethods, _RestrictedTreeConfigOffBase
):
    """Feature disabled — all directories accessible."""

    expect_restricted: bool = False
