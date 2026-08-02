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
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe_mod.addImport("bpf_programs", bpf_programs_module);
    configureLibbpfModule(b, exe_mod, dependencies);
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
    test_mod.addImport("bpf_programs", bpf_programs_module);
    configureLibbpfModule(b, test_mod, dependencies);
    const unit_tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
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
