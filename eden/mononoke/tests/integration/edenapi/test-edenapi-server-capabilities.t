# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This software may be used and distributed according to the terms of the
# GNU General Public License found in the LICENSE file in the root
# directory of this source tree.

  $ . "${TEST_FIXTURES}/library.sh"

Set up local hgrc and Mononoke config.
  $ quiet default_setup_blobimport
  $ setup_configerator_configs

  $ start_and_wait_for_mononoke_server
  $ sslcurlas client0 -s "https://localhost:$MONONOKE_SOCKET/edenapi/repo/capabilities"
  ["sapling-common","commit-graph-segments","commit-cloud"] (no-eol)

  $ sslcurlas client0 -s "https://localhost:$MONONOKE_SOCKET/slapigit/repo/capabilities"
  [] (no-eol)
