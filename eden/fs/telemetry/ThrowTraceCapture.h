/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#pragma once

#include <optional>
#include <string>

namespace facebook::eden {

/**
 * Returns the throw-site stack trace for the current exception.
 * Must be called inside a catch block.
 *
 * Uses backtrace-rs via Rust FFI for cross-platform stack trace capture.
 * Raw IP addresses are captured at throw time; symbolization is deferred
 * until this function is called (lazy symbolization).
 *
 * Platform-specific hooks:
 *   Linux:   __wrap___cxa_throw (via --wrap linker flag)
 *   macOS:   __cxa_throw override (via dlsym RTLD_NEXT)
 */
std::optional<std::string> getThrowSiteStackTrace();

} // namespace facebook::eden
