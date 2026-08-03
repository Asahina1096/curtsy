//! Privileged test-suite entry point (run via `zig build test-ebpf`).
//!
//! Same module tree as the default suite, but the run step sets
//! CURTSY_ENABLE_EBPF_TESTS and CURTSY_REQUIRE_EBPF_TESTS so the privileged
//! eBPF integration tests run for real and FAIL LOUDLY when the environment
//! lacks the required capabilities/kernel support, instead of skipping like
//! they do in the default `zig build test`. Keep the imports in sync with
//! test.zig.

test {
    _ = @import("net.zig");
    _ = @import("yaml.zig");
    _ = @import("module.zig");
    _ = @import("conf.zig");
    _ = @import("modules/core.zig");
    _ = @import("log.zig");
    _ = @import("autotune.zig");
    _ = @import("modules/upstream.zig");
    _ = @import("modules/rules.zig");
    _ = @import("modules/timeouts.zig");
    _ = @import("modules/limits.zig");
    _ = @import("modules/logging.zig");
    _ = @import("modules/runtime.zig");
    _ = @import("modules/performance.zig");
    _ = @import("modules/tcp.zig");
    _ = @import("modules/udp.zig");
    _ = @import("modules/tuning.zig");
    _ = @import("modules/balancer/round_robin.zig");
    _ = @import("modules/balancer/source_hash.zig");
    _ = @import("modules/balancer/weighted_round_robin.zig");
    _ = @import("bpf.zig");
}
