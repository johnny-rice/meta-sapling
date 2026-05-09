#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2.

# pyre-unsafe

"""Lightweight wrapper around a Sapling eagerepo, used by integration tests
that need to populate a server-authoritative repo (one that EdenFS pulls
trees from via SLAPI) with normal-looking commit operations.

Unlike HgRepository's ``init`` -- which creates a *client* repo whose
``paths.default`` points at an eagerepo created elsewhere -- ``EagerRepo``
creates the eagerepo itself via ``sl init --config format.use-eager-repo=true``.
Subsequent Sapling operations in that working copy write directly into the
eagerepo's zstore, which is the same storage served by ``eager://<path>``.
Most repo-manipulation helpers come from ``HgRepository``; this class mainly
customizes ``init()`` so tests can create and configure the eagerepo itself.
"""

import configparser
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

from . import hgrepo


class EagerRepo(hgrepo.HgRepository):
    """A working-copy hg repo backed by eagerepo storage.

    ``path`` is the on-disk directory where the eagerepo is created. The
    same directory is what ``eager://<path>`` URLs resolve to: writes here
    are visible to clients that pull from this repo via SLAPI.
    """

    def __init__(
        self,
        path: Union[str, Path],
        hg_environment: Dict[str, str],
        system_hgrc: Optional[str] = None,
    ) -> None:
        super().__init__(str(path))
        # Inherit the caller's already-isolated env (HGPLAIN, HGRCPATH, etc.)
        # so the eagerepo runs with the same hgrc rules as the backing repo.
        self.hg_environment = dict(hg_environment)
        if system_hgrc is not None:
            # Match HgRepository's HGRCPATH form so static configs (e.g. fb)
            # plus the test's overrides are both loaded.
            self.hg_environment["HGRCPATH"] = "fb=static;" + system_hgrc

    def init(
        self,
        hgrc: Optional[configparser.ConfigParser] = None,
        init_configs: Optional[List[str]] = None,
    ) -> None:
        """Create the eagerepo at ``self.path``.

        Idempotent: if ``.hg`` already exists, this is a no-op.
        """
        if os.path.isdir(os.path.join(self.path, ".hg")):
            return
        os.makedirs(self.path, exist_ok=True)
        init_config_args = [f"--config={c}" for c in init_configs or ()]
        # ``sl init --config format.use-eager-repo=true <path>`` opens the
        # eagerepo and writes a working-copy hg layout on top of it.
        self.hg(
            "init",
            *init_config_args,
            "--config=format.use-eager-repo=true",
            self.path,
            cwd=os.path.dirname(self.path) or self.path,
        )

        if hgrc is None:
            hgrc = configparser.ConfigParser()

        self.write_hgrc(hgrc)
