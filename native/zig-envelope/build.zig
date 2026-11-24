const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const module = b.addModule("zig_envelope", .{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize });
    const tests = b.addTest(.{ .root_module = module });
    const run_tests = b.addRunArtifact(tests);
    const step = b.step("test", "Run native envelope tests");
    step.dependOn(&run_tests.step);
}
