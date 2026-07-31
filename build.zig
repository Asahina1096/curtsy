const std = @import("std");

pub fn build(b: *std.Build) void {
    // Default to the arch baseline CPU so release binaries (e.g. the Debian
    // package) run on any machine; pass -Dcpu=native to optimize for the
    // build host.
    const target = b.standardTargetOptions(.{
        .default_target = .{ .cpu_model = .baseline },
    });
    const optimize = b.standardOptimizeOption(.{});

    // libc is required for getaddrinfo/inet_pton/inet_ntop in net.zig.
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const exe = b.addExecutable(.{
        .name = "curtsy",
        .root_module = exe_mod,
        .version = .{ .major = 0, .minor = 3, .patch = 0 },
    });
    exe.pie = true;
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run curtsy");
    run_step.dependOn(&run_cmd.step);

    // Unit tests live in the same source files; main.zig transitively imports
    // the runtime modules so their tests run too.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
