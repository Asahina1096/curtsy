const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const local_zig = requireLocalZig(b);

    // Default to the arch baseline CPU so release binaries (e.g. the Debian
    // package) run on any machine; pass -Dcpu=native to optimize for the
    // build host.
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = builtin.cpu.arch,
            .os_tag = .linux,
            .abi = .gnu,
            .cpu_model = .baseline,
        },
    });
    const optimize = b.standardOptimizeOption(.{});
    const bpf_target = if (target.result.cpu.arch.endian() == .little)
        "bpfel-freestanding"
    else
        "bpfeb-freestanding";
    const dependencies = localDependencies(b, target.result.cpu.arch);

    const generated_bpf = b.addWriteFiles();
    _ = generated_bpf.addCopyFile(
        compileBpfObject(b, local_zig, bpf_target, dependencies.include_dir, "src/ebpf/tcp_sockmap.bpf.c", "tcp_sockmap"),
        "tcp_sockmap.bpf.o",
    );
    _ = generated_bpf.addCopyFile(
        compileBpfObject(b, local_zig, bpf_target, dependencies.include_dir, "src/ebpf/udp_sockmap.bpf.c", "udp_sockmap"),
        "udp_sockmap.bpf.o",
    );
    _ = generated_bpf.addCopyFile(
        compileBpfObject(b, local_zig, bpf_target, dependencies.include_dir, "src/ebpf/reuseport.bpf.c", "reuseport"),
        "reuseport.bpf.o",
    );
    _ = generated_bpf.addCopyFile(
        compileBpfObject(b, local_zig, bpf_target, dependencies.include_dir, "src/ebpf/observer.bpf.c", "observer"),
        "observer.bpf.o",
    );
    const bpf_programs_source = generated_bpf.add("programs.zig",
        \\pub const tcp_sockmap = @embedFile("tcp_sockmap.bpf.o");
        \\pub const udp_sockmap = @embedFile("udp_sockmap.bpf.o");
        \\pub const reuseport = @embedFile("reuseport.bpf.o");
        \\pub const observer = @embedFile("observer.bpf.o");
        \\
    );
    const bpf_programs_module = b.createModule(.{ .root_source_file = bpf_programs_source });

    // libc is required for getaddrinfo/inet_pton/inet_ntop in net.zig.
    const exe_mod = runtimeModule(b, b.path("src/main.zig"), target, optimize, bpf_programs_module, dependencies);
    const exe = b.addExecutable(.{
        .name = "curtsy",
        .root_module = exe_mod,
        .version = .{ .major = 0, .minor = 3, .patch = 2 },
    });
    exe.pie = true;
    // A deterministic content-based ELF build id (.note.gnu.build-id) lets the
    // Debian package coordinate a stripped binary with its debug symbols and
    // keeps debuginfod/build-id tooling working.
    exe.build_id = .sha1;
    b.installArtifact(exe);

    // Reference implementation of the versioned C plugin ABI. Production
    // deployments may install independently built libraries and list their
    // absolute paths in `plugins:`; this artifact also drives the integration
    // probe below.
    const sample_plugin_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sample_plugin_mod.addIncludePath(b.path("include"));
    sample_plugin_mod.addCSourceFile(.{
        .file = b.path("examples/plugins/hello.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Werror" },
    });
    const sample_plugin = b.addLibrary(.{
        .name = "curtsy_plugin_hello",
        .root_module = sample_plugin_mod,
        .linkage = .dynamic,
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
    });
    const install_sample_plugin = b.addInstallArtifact(sample_plugin, .{});
    const protocol_probe_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    protocol_probe_mod.addIncludePath(b.path("include"));
    protocol_probe_mod.addCSourceFile(.{
        .file = b.path("examples/plugins/protocol_probe.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Werror" },
    });
    const protocol_probe = b.addLibrary(.{
        .name = "curtsy_plugin_protocol_probe",
        .root_module = protocol_probe_mod,
        .linkage = .dynamic,
    });
    const plugin_step = b.step("plugin-example", "Build and install the example runtime plugin");
    plugin_step.dependOn(&install_sample_plugin.step);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run curtsy");
    run_step.dependOn(&run_cmd.step);

    // Unit tests live in the same source files; the test root in src/test.zig
    // aggregates the runtime modules so their tests run as one suite. Both
    // the compile and run tasks share the same filtered artifact.
    const test_filter = b.option([]const u8, "test-filter", "Only run tests whose names contain this substring");
    const test_filters: []const []const u8 = if (test_filter) |filter| &.{filter} else &.{};
    const test_mod = runtimeModule(b, b.path("src/test.zig"), target, optimize, bpf_programs_module, dependencies);
    const unit_tests = b.addTest(.{ .root_module = test_mod, .filters = test_filters });

    const test_compile_step = b.step("test-compile", "Compile the unit test suite without running it");
    test_compile_step.dependOn(&unit_tests.step);

    const run_tests = b.addRunArtifact(unit_tests);
    const plugin_probe_mod = runtimeModule(b, b.path("src/plugin_integration.zig"), target, optimize, bpf_programs_module, dependencies);
    const plugin_probe = b.addExecutable(.{ .name = "plugin-integration", .root_module = plugin_probe_mod });
    const run_plugin_probe = b.addRunArtifact(plugin_probe);
    run_plugin_probe.addFileArg(sample_plugin.getEmittedBin());
    run_plugin_probe.addFileArg(protocol_probe.getEmittedBin());
    const run_cli_plugin_probe = b.addRunArtifact(exe);
    run_cli_plugin_probe.addArg("--check-config");
    run_cli_plugin_probe.addArg("--plugin");
    run_cli_plugin_probe.addFileArg(sample_plugin.getEmittedBin());
    run_cli_plugin_probe.addArgs(&.{ "--plugin-config", "message=cli-integration" });
    run_cli_plugin_probe.addArg("--plugin");
    run_cli_plugin_probe.addFileArg(protocol_probe.getEmittedBin());
    run_cli_plugin_probe.addArgs(&.{
        "--rule",
        "listen=127.0.0.1:9000,upstreams=127.0.0.1:9001,127.0.0.1:9002,protocols=probe_udp,balance=first_available",
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_plugin_probe.step);
    test_step.dependOn(&run_cli_plugin_probe.step);

    // Privileged eBPF integration suite: a separate test root run with the
    // eBPF gates enabled and REQUIRED, so missing CAP_BPF/CAP_NET_ADMIN (or an
    // unsupported kernel) fails loudly instead of silently skipping. The step
    // runs the whole module tree (the two gated tests are always part of it,
    // so it can never silently select zero tests); pass -Dtest-filter to focus.
    // Run as root: `.toolchain/zig/zig build test-ebpf`.
    const ebpf_test_mod = runtimeModule(b, b.path("src/test_ebpf.zig"), target, optimize, bpf_programs_module, dependencies);
    const ebpf_tests = b.addTest(.{ .root_module = ebpf_test_mod, .filters = test_filters });
    const run_ebpf_tests = b.addRunArtifact(ebpf_tests);
    run_ebpf_tests.setEnvironmentVariable("CURTSY_ENABLE_EBPF_TESTS", "1");
    run_ebpf_tests.setEnvironmentVariable("CURTSY_REQUIRE_EBPF_TESTS", "1");
    const test_ebpf_step = b.step("test-ebpf", "Run the privileged eBPF integration suite (requires root/CAP_BPF/CAP_NET_ADMIN); fails loudly without them");
    test_ebpf_step.dependOn(&run_ebpf_tests.step);
}

fn runtimeModule(
    b: *std.Build,
    root_source_file: std.Build.LazyPath,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    bpf_programs_module: *std.Build.Module,
    dependencies: LocalDependencies,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("bpf_programs", bpf_programs_module);
    configureLibbpfModule(b, module, dependencies);
    return module;
}

fn compileBpfObject(
    b: *std.Build,
    local_zig: []const u8,
    bpf_target: []const u8,
    include_dir: []const u8,
    source_path: []const u8,
    output_name: []const u8,
) std.Build.LazyPath {
    const compile = b.addSystemCommand(&.{
        local_zig,
        "cc",
        "-target",
        bpf_target,
        "-O2",
        "-g",
        "-Wall",
        "-Werror",
        "-fno-stack-protector",
        "-c",
    });
    compile.addArg("-I");
    compile.addArg(include_dir);
    compile.addFileInput(b.path("src/ebpf/common.h"));
    compile.addFileArg(b.path(source_path));
    compile.addArg("-o");
    return compile.addOutputFileArg(b.fmt("{s}.bpf.o", .{output_name}));
}

fn configureLibbpfModule(
    b: *std.Build,
    module: *std.Build.Module,
    dependencies: LocalDependencies,
) void {
    module.addCSourceFile(.{
        .file = b.path("src/libbpf_shim.c"),
        .flags = &.{ "-std=c11", "-Wall", "-Werror" },
    });
    module.addIncludePath(.{ .cwd_relative = dependencies.include_dir });
    module.addObjectFile(.{ .cwd_relative = dependencies.libbpf });
    module.addObjectFile(.{ .cwd_relative = dependencies.libelf });
    module.addObjectFile(.{ .cwd_relative = dependencies.libz });
    module.addObjectFile(.{ .cwd_relative = dependencies.libzstd });
}

const LocalDependencies = struct {
    include_dir: []const u8,
    libbpf: []const u8,
    libelf: []const u8,
    libz: []const u8,
    libzstd: []const u8,
};

fn requireLocalZig(b: *std.Build) []const u8 {
    if (builtin.zig_version.major != 0 or builtin.zig_version.minor != 16 or builtin.zig_version.patch != 0) {
        @panic("this build requires the pinned Zig 0.16.0 toolchain");
    }
    const expected = b.pathFromRoot(".toolchain/zig/zig");
    std.Io.Dir.accessAbsolute(b.graph.io, expected, .{}) catch {
        @panic("local Zig toolchain is missing; run tools/bootstrap-build-deps.sh");
    };
    const invoked = std.fs.path.resolve(b.allocator, &.{b.graph.zig_exe}) catch @panic("out of memory");
    if (!std.mem.eql(u8, expected, invoked)) {
        @panic("system Zig is not supported; run .toolchain/zig/zig build");
    }
    return expected;
}

fn localDependencies(b: *std.Build, arch: std.Target.Cpu.Arch) LocalDependencies {
    const triple = switch (arch) {
        .x86_64 => "x86_64-linux-gnu",
        else => @panic("local libbpf dependencies are not available for this target architecture"),
    };
    const root = b.pathFromRoot(b.fmt(".toolchain/deps/{s}/usr", .{triple}));
    const include_dir = b.fmt("{s}/include", .{root});
    const library_dir = b.fmt("{s}/lib/x86_64-linux-gnu", .{root});
    const dependencies = LocalDependencies{
        .include_dir = include_dir,
        .libbpf = b.fmt("{s}/libbpf.a", .{library_dir}),
        .libelf = b.fmt("{s}/libelf.a", .{library_dir}),
        .libz = b.fmt("{s}/libz.a", .{library_dir}),
        .libzstd = b.fmt("{s}/libzstd.a", .{library_dir}),
    };
    inline for (.{
        b.fmt("{s}/bpf/libbpf.h", .{dependencies.include_dir}),
        dependencies.libbpf,
        dependencies.libelf,
        dependencies.libz,
        dependencies.libzstd,
    }) |path| {
        std.Io.Dir.accessAbsolute(b.graph.io, path, .{}) catch {
            @panic("local libbpf dependencies are missing; run tools/bootstrap-build-deps.sh");
        };
    }
    return dependencies;
}
