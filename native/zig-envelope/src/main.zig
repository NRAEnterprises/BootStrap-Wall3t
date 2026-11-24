const std = @import("std");

pub const Envelope = struct {
    version: u8,
    payload: []const u8,
};

pub fn parse(bytes: []const u8) !Envelope {
    if (bytes.len < 2) return error.InvalidEnvelope;
    if (bytes[0] != 1) return error.UnsupportedVersion;
    return .{ .version = bytes[0], .payload = bytes[1..] };
}

test "parses versioned secret-free envelope" {
    const envelope = try parse(&[_]u8{ 1, 9, 8 });
    try std.testing.expectEqual(@as(u8, 1), envelope.version);
    try std.testing.expectEqual(@as(usize, 2), envelope.payload.len);
}
