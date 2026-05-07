/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include "eden/fs/telemetry/ThrowTraceCapture.h"

#include <cstdlib>

#ifdef __APPLE__
#include <dlfcn.h>
#endif

#include "eden/fs/rust/backtrace_ffi/src/lib.rs.h"

#if defined(__linux__) || defined(__APPLE__)

namespace {
// Common: onThrow() captures a raw backtrace via Rust FFI.
// Re-entrancy is handled by the Rust CapturingGuard in capture_backtrace().
void onThrow() {
  constexpr size_t kMaxStackDepth = 64;
  facebook::eden::capture_backtrace(kMaxStackDepth);
}
} // namespace

#if defined(__linux__)
// Linux throw hook using the GNU linker's --wrap mechanism.
//
// When -Wl,--wrap=__cxa_throw is passed (via exported_linker_flags in BUCK),
// the linker redirects all calls to __cxa_throw to __wrap___cxa_throw, and
// makes the original available as __real___cxa_throw. This lets us intercept
// every C++ throw to capture a backtrace before the stack unwinds.
//
// Flow: throw expr → __wrap___cxa_throw → onThrow() → capture_backtrace()
//       → __real___cxa_throw (original, performs the actual throw)

extern "C" {
void __real___cxa_throw(void*, void*, void (*)(void*))
    __attribute__((__noreturn__));

__attribute__((__noreturn__)) void __wrap___cxa_throw(
    void* thrownException,
    void* type,
    void (*destructor)(void*)) {
  onThrow();
  __real___cxa_throw(thrownException, type, destructor);
  __builtin_unreachable();
}
} // extern "C"

#elif defined(__APPLE__)
// macOS: Override __cxa_throw, delegate to original via dlsym(RTLD_NEXT).

using CxaThrowFn = void (*)(void*, void*, void (*)(void*));

extern "C" __attribute__((__noreturn__)) void
__cxa_throw(void* thrownException, void* type, void (*destructor)(void*)) {
  onThrow();
  static auto orig =
      reinterpret_cast<CxaThrowFn>(dlsym(RTLD_NEXT, "__cxa_throw"));
  if (!orig) {
    std::abort();
  }
  orig(thrownException, type, destructor);
  __builtin_unreachable();
}

#endif // platform hooks

#endif // defined(__linux__) || defined(__APPLE__)

namespace facebook::eden {

// Lazy symbolization via Rust FFI — resolves captured frames on demand.
std::optional<std::string> getThrowSiteStackTrace() {
  auto trace = symbolize_captured_trace();
  if (trace.empty()) {
    return std::nullopt;
  }
  return std::string(trace.data(), trace.size());
}

} // namespace facebook::eden
