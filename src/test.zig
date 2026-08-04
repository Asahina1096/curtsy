//! Test-suite entry point.
//!
//! Aggregates the module tree so that the tests living alongside each module
//! (see AGENTS.md test strategy) are compiled and run as one suite. Keeping the
//! registry here instead of main.zig decouples test registration from the CLI
//! entry point: production builds import main.zig, test builds import this
//! root. build.zig wires this file as the test module root source.

test {
    _ = @import("net.zig");
    _ = @import("yaml.zig");
    _ = @import("module.zig");
    _ = @import("conf.zig");
    _ = @import("modules/core.zig");
    _ = @import("plugin.zig");
    _ = @import("modules/plugins.zig");
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
