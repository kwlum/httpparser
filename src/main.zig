// Inspired by picohttpparser and rust httparse.
const std = @import("std");
const mem = std.mem;

const uri_map = [_]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const header_name_map = [_]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

const header_value_map = [_]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

inline fn isToken(c: u8) bool {
    return (c > 0x1F and c < 0x7F);
}

inline fn isUriToken(c: u8) bool {
    return (uri_map[c] == 1);
}

inline fn isHeaderNameToken(c: u8) bool {
    return header_name_map[c] == 1;
}

inline fn isHeaderValueToken(c: u8) bool {
    return header_value_map[c] == 1;
}

pub const ParseError = error{
    InvalidHeaderName,
    InvalidHeaderValue,
    InvalidNewLine,
    InvalidStatus,
    InvalidToken,
    InvalidMethod,
    TooManyHeaders,
    InvalidUri,
    InvalidHttpVersion,
    InvalidChunkSize,
    NewLineFound,
    InvalidVersion,
    InvalidReason,
    Eof,
} || std.mem.Allocator.Error;

fn findCharFast(buf: []const u8, comptime needles: []const u8) ?usize {
    const indices = @Vector(16, u8){ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const zeroes = @splat(16, @as(u8, 0));
    const flags = @splat(16, @as(u8, 20));

    comptime var needle: [needles.len]@Vector(16, u8) = undefined;
    inline for (needles, 0..) |a, i| {
        needle[i] = @splat(16, @as(u8, a));
    }

    var pos: usize = 0;
    while (pos + 15 < buf.len) : (pos += 16) {
        const haystack: @Vector(16, u8) = buf[pos..][0..16].*;
        var result = @splat(16, @as(u8, 0));

        inline for (needle) |a| {
            const r2 = @select(u8, haystack == a, indices, zeroes);
            result = result | r2;
        }

        const r3 = @select(u8, result == zeroes, flags, indices);
        const r4 = @reduce(.Min, r3);
        if (r4 != 20) return pos + r4 - 1;
    }

    while (pos < buf.len) : (pos += 1) {
        for (needles) |n| {
            if (buf[pos] == n) return pos;
        }
    }

    return null;
}

fn parseToken(buf: []const u8, token: *[]const u8) ParseError![]const u8 {
    if (buf.len == 0) return ParseError.Eof;
    if (!isToken(buf[0])) return ParseError.InvalidToken;

    for (buf, 0..) |a, i| {
        if (a == ' ') {
            token.* = buf[0..i];
            return buf[(i + 1)..];
        } else if (!isToken(a)) {
            return ParseError.InvalidToken;
        }
    } else {
        return ParseError.Eof;
    }
}

fn parseMethod(buf: []const u8, method: *[]const u8) ParseError![]const u8 {
    return parseToken(buf, method);
}

fn parseUri(buf: []const u8, uri: *[]const u8) ParseError![]const u8 {
    if (buf.len == 0) return ParseError.Eof;
    if (!isUriToken(buf[0])) return ParseError.InvalidToken;

    if (findCharFast(buf, "\x00\x20\x7f")) |i| {
        if (buf[i] == ' ') {
            uri.* = buf[0..i];
            return buf[(i + 1)..];
        } else if (!isUriToken(buf[i])) {
            return ParseError.InvalidToken;
        }
    }

    return ParseError.Eof;
}

fn parseVersion(buf: []const u8, version: *u8) ParseError![]const u8 {
    if (buf.len < 8) return ParseError.Eof;

    inline for ("HTTP/1.", 0..) |a, i| {
        if (a != buf[i]) return ParseError.InvalidVersion;
    }

    switch (buf[7]) {
        '1' => {
            version.* = 1;
            return buf[8..];
        },
        '0' => {
            version.* = 0;
            return buf[8..];
        },
        else => return ParseError.InvalidVersion,
    }
}

const ParseCodeValue = struct {
    buffer: []const u8,
    code: u16,
};

fn parseCode(buf: []const u8, code: *u16) ParseError![]const u8 {
    if (buf.len < 3) {
        return ParseError.Eof;
    } else if (!std.ascii.isDigit(buf[0]) or
        !std.ascii.isDigit(buf[1]) or
        !std.ascii.isDigit(buf[2]))
    {
        return ParseError.InvalidStatus;
    } else {
        var c: u16 = @as(u16, (buf[0] - '0')) * 100;
        c += @as(u16, (buf[1] - '0')) * 10;
        c += buf[2] - '0';

        code.* = c;

        return buf[3..];
    }
}

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

fn parseHeaders(buf: []const u8, headers: []Header, header_len: *usize) ParseError![]const u8 {
    var header_index: usize = 0;
    var rest = buf;
    rest = headers_blk: while (true) {
        if (rest.len == 0) return ParseError.Eof;

        // End of headers if new line found.
        if (rest[0] == '\r') {
            if (rest.len < 2) return ParseError.Eof;
            if (rest[1] != '\n') return ParseError.InvalidNewLine;
            break :headers_blk rest[2..];
        }

        if (rest[0] == '\n') break :headers_blk rest[1..];

        if (!isHeaderNameToken(rest[0])) {
            return ParseError.InvalidHeaderName;
        }

        var header_name: []const u8 = undefined;
        var header_value: []const u8 = undefined;
        // Parse header name.
        rest = header_name_blk: {
            var line = rest;
            for (line, 0..) |a, i| {
                if (!isHeaderNameToken(a)) {
                    header_name = line[0..i];
                    line = line[i..];
                    break;
                }
            } else {
                return ParseError.Eof;
            }

            if (line[0] == ':') break :header_name_blk line[1..];

            return ParseError.InvalidHeaderName;
        };

        rest = header_value_blk: {
            var line = rest;
            // Skip whitespace.
            for (line, 0..) |a, i| {
                if (a == ' ' or a == '\t') continue;
                if (isHeaderValueToken(a)) {
                    line = line[i..];
                    break;
                }

                if (a == '\r') {
                    if (i + 1 >= line.len) return ParseError.Eof;
                    if (line[i + 1] != '\n') return ParseError.InvalidHeaderValue;
                } else if (a != '\n') {
                    return ParseError.InvalidHeaderValue;
                }

                header_value = "";
                break :header_value_blk line[i..];
            } else {
                return ParseError.Eof;
            }

            // Attempt to get the header value.
            if (findCharFast(line, "\x00\x08\x0A\x1F\x7F\x0D")) |k| {
                header_value = line[0..k];
                line = line[k..];
            } else {
                return ParseError.Eof;
            }

            if (line[0] == '\n') break :header_value_blk line[1..];
            if (line.len > 1 and line[0] == '\r' and line[1] == '\n') break :header_value_blk line[2..];

            return ParseError.InvalidHeaderValue;
        };

        // Append header into headers, otherwise ignore the rest of headers.
        if (header_index >= headers.len) return ParseError.TooManyHeaders;

        headers[header_index] = .{
            .name = header_name,
            .value = trimRight(header_value),
        };
        header_index += 1;
    };

    header_len.* = header_index;
    return rest;
}

fn trimRight(str: []const u8) []const u8 {
    var i: usize = str.len;
    while (i > 0) : (i -= 1) {
        const c = str[i - 1];
        if (c != ' ' and c != '\t') break;
    }

    return str[0..i];
}

fn skipReason(buf: []const u8) ParseError![]const u8 {
    for (buf, 0..) |a, i| {
        if (a == '\n') {
            return buf[(i + 1)..];
        } else if (a == '\r') {
            if (i + 1 >= buf.len) return ParseError.Eof;
            if (buf[i + 1] != '\n') return ParseError.InvalidReason;
            return buf[(i + 2)..];
        }
    } else {
        return ParseError.Eof;
    }
}

fn skipEmptyLines(buf: []const u8) ParseError![]const u8 {
    if (buf.len == 0) return ParseError.Eof;

    var start: usize = 0;
    for (buf, 0..) |a, i| {
        switch (a) {
            '\n' => start = i + 1,
            '\r' => {
                if (i + 1 >= buf.len) return ParseError.Eof;
                if (buf[i + 1] != '\n') return ParseError.InvalidNewLine;
            },
            else => return buf[start..],
        }
    } else {
        return ParseError.Eof;
    }
}

fn skipSpaces(buf: []const u8) ParseError![]const u8 {
    if (buf.len == 0) return ParseError.Eof;

    for (buf, 0..) |a, i| {
        switch (a) {
            ' ' => {},
            else => return buf[i..],
        }
    } else {
        return ParseError.Eof;
    }
}

fn parseNewLine(buf: []const u8) ParseError![]const u8 {
    if (buf.len == 0) return ParseError.Eof;

    switch (buf[0]) {
        '\n' => return buf[1..],
        '\r' => {
            if (buf.len < 2) return ParseError.Eof;
            if (buf[1] != '\n') return ParseError.InvalidNewLine;
            return buf[2..];
        },
        else => return ParseError.InvalidNewLine,
    }
}

pub const Request = struct {
    method: ?[]const u8 = null,
    path: ?[]const u8 = null,
    version: ?u8 = null,
    headers: []Header,
    in_headers: []Header,
    payload: ?[]const u8 = null,

    const Self = @This();

    pub fn init(headers: []Header) Request {
        return .{
            .in_headers = headers,
            .headers = headers[0..0],
        };
    }

    pub fn parse(self: *Request, buf: []const u8) ParseError!void {
        var method: []const u8 = undefined;
        var uri: []const u8 = undefined;
        var version: u8 = 0;

        var rest = try skipEmptyLines(buf);
        rest = try parseMethod(rest, &method);
        rest = try skipSpaces(rest);
        rest = try parseUri(rest, &uri);
        rest = try skipSpaces(rest);
        rest = try parseVersion(rest, &version);
        rest = try parseNewLine(rest);

        var headers_len: usize = 0;
        rest = try parseHeaders(rest, self.in_headers, &headers_len);
        self.headers = self.in_headers[0..headers_len];

        self.method = method;
        self.path = uri;
        self.version = version;
        if (rest.len > 0) self.payload = rest;
    }
};

pub const Response = struct {
    version: ?u8 = null,
    code: ?u16 = null,
    headers: []Header,
    in_headers: []Header,

    const Self = @This();

    pub fn init(headers: []Header) Response {
        return .{
            .headers = headers[0..0],
            .in_headers = headers,
        };
    }

    pub fn parse(self: *Self, buf: []const u8) ParseError!void {
        var version: u8 = 0;
        var code: u16 = 404;

        var rest = try skipEmptyLines(buf);
        rest = try parseVersion(rest, &version);
        rest = try skipSpaces(rest);
        rest = try parseCode(rest, &code);
        rest = try skipReason(rest);

        var headers_len: usize = 0;
        rest = try parseHeaders(rest, self.in_headers, &headers_len);
        self.headers = self.in_headers[0..headers_len];
        self.code = code;
        self.version = version;
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
    }
};

const ParseChunkSizeValue = struct {
    pos: usize,
    len: u64,
};

const hex_string = "0123456789abcdefABCDEF";

pub fn parseChunkSize(buf: []const u8) ParseError!ParseChunkSizeValue {
    // Read the chunk size.
    var chunk_size: u64 = 0;
    var chunk_count: u16 = 0;
    var index: usize = 0;
    var rest = buf;

    for (rest, 0..) |token, k| {
        if (std.mem.indexOfScalar(u8, hex_string, token)) |i| {
            if (chunk_count > 15) {
                return ParseError.InvalidChunkSize;
            }

            chunk_count += 1;
            var value: u64 = 0;

            if (i < 10) {
                // Value in 0123456789.
                value = token - '0';
            } else if (i < 16) {
                // Value in abcdef.
                value = token - 'a' + 10;
            } else {
                // Value in ABCDEF.
                value = token - 'A' + 10;
            }

            chunk_size = chunk_size * 16 + value;
        } else if (std.mem.indexOfScalar(u8, "; \t", token)) |_| {
            // Stop when one of whitespace \t ; is found.
            index = k;
            rest = rest[k..];
            break;
        } else if (token == '\r') {
            if (k + 1 >= buf.len) return ParseError.Eof;
            if (buf[k + 1] == '\n') {
                return ParseChunkSizeValue{
                    .pos = k + 2,
                    .len = chunk_size,
                };
            } else {
                return ParseError.InvalidChunkSize;
            }
        } else {
            return ParseError.InvalidChunkSize;
        }
    } else {
        return ParseError.Eof;
    }

    // Ignore extension, linear white space, read until \r\n.
    for (rest, 0..) |token, k| {
        if (token == '\r') {
            if (k + 1 >= rest.len) return ParseError.Eof;

            if (rest[k + 1] == '\n') {
                return ParseChunkSizeValue{
                    .pos = index + k + 2,
                    .len = chunk_size,
                };
            } else {
                return ParseError.InvalidChunkSize;
            }
        }
    } else {
        return ParseError.Eof;
    }
}

test "request simple" {
    const header = "GET / HTTP/1.1\r\n\r\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 0), req.headers.len);
}

test "request with query params" {
    const header = "GET /search?keyword=world HTTP/1.1\r\n\r\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/search?keyword=world", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 0), req.headers.len);
}

test "request with whatwg query params" {
    const header = "GET /search?keyword=world^ HTTP/1.1\r\n\r\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/search?keyword=world^", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 0), req.headers.len);
}

test "request headers" {
    const header = "GET / HTTP/1.1\r\nHost: hello.com\r\nCookie: \r\n\r\n";
    var headers: [4]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 2), req.headers.len);
    try std.testing.expectEqualStrings("Host", req.headers[0].name);
    try std.testing.expectEqualStrings("hello.com", req.headers[0].value);
    try std.testing.expectEqualStrings("Cookie", req.headers[1].name);
    try std.testing.expectEqualStrings("", req.headers[1].value);
}

test "request headers with optional whitespace" {
    const header = "GET / HTTP/1.1\r\nHost: \tfoo.com\t \r\nCookie: \t \r\n\r\n";
    var headers: [4]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 2), req.headers.len);
    try std.testing.expectEqualStrings("Host", req.headers[0].name);
    try std.testing.expectEqualStrings("foo.com", req.headers[0].value);
    try std.testing.expectEqualStrings("Cookie", req.headers[1].name);
    try std.testing.expectEqualStrings("", req.headers[1].value);
}

test "request headers value htab short" {
    const header = "GET / HTTP/1.1\r\nUser-Agent: some\tagent\r\n\r\n";
    var headers: [4]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 1), req.headers.len);
    try std.testing.expectEqualStrings("User-Agent", req.headers[0].name);
    try std.testing.expectEqualStrings("some\tagent", req.headers[0].value);
}

test "request headers value htab long" {
    const header = "GET / HTTP/1.1\r\nUser-Agent: 1234567890some\t1234567890agent1234567890\r\n\r\n";
    var headers: [4]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 1), req.headers.len);
    try std.testing.expectEqualStrings("User-Agent", req.headers[0].name);
    try std.testing.expectEqualStrings("1234567890some\t1234567890agent1234567890", req.headers[0].value);
}

test "request multibyte" {
    const header = "GET / HTTP/1.1\r\nHost: foo.com\r\nUser-Agent: \xe3\x81\xb2\xe3/1.0\r\n\r\n";
    var headers: [4]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 2), req.headers.len);
    try std.testing.expectEqualStrings("Host", req.headers[0].name);
    try std.testing.expectEqualStrings("foo.com", req.headers[0].value);
    try std.testing.expectEqualStrings("User-Agent", req.headers[1].name);
    try std.testing.expectEqualStrings("\xe3\x81\xb2\xe3/1.0", req.headers[1].value);
}

test "request partial" {
    const header = "GET / HTTP/1.1\r\n\r";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    var result = req.parse(header);

    try std.testing.expectError(ParseError.Eof, result);
}

test "request partial version" {
    const header = "GET / HTTP/1.";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    var result = req.parse(header);

    try std.testing.expectError(ParseError.Eof, result);
}

test "request new lines" {
    const header = "GET / HTTP/1.1\nHost: foo.bar\n\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 1), req.headers.len);
    try std.testing.expectEqualStrings("Host", req.headers[0].name);
    try std.testing.expectEqualStrings("foo.bar", req.headers[0].value);
}

test "request empty lines prefix" {
    const header = "\r\n\r\nGET / HTTP/1.1\r\n\r\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 0), req.headers.len);
}

test "request empty lines prefix if only" {
    const header = "\n\nGET / HTTP/1.1\n\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 0), req.headers.len);
}

test "request path backslash" {
    const header = "\n\nGET /\\?wayne\\=5 HTTP/1.1\n\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    try req.parse(header);

    try std.testing.expectEqualStrings("GET", req.method.?);
    try std.testing.expectEqualStrings("/\\?wayne\\=5", req.path.?);
    try std.testing.expectEqual(@as(u8, 1), req.version.?);
    try std.testing.expectEqual(@as(usize, 0), req.headers.len);
}

test "request invalid token delimiter" {
    const header = "GET\n/ HTTP/1.1\r\nHost: foo.bar\r\n\r\n";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    const result = req.parse(header);

    try std.testing.expectError(ParseError.InvalidToken, result);
}

test "request not enough" {
    const header = "GET / HTTP/1!";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    const result = req.parse(header);

    try std.testing.expectError(ParseError.Eof, result);
}

test "request invalid version" {
    const header = "GET / HTTP/1.!";
    var headers: [1]Header = undefined;
    var req = Request.init(&headers);
    const result = req.parse(header);

    try std.testing.expectError(ParseError.InvalidVersion, result);
}

test "response simple" {
    const header = "HTTP/1.1 200 OK\r\n\r\n";
    var headers: [1]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 200), res.code.?);
    try std.testing.expectEqual(@as(u8, 1), res.version.?);
}

test "response new line" {
    const header = "HTTP/1.0 403 Forbidden\nServer: foo.bar\n\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 403), res.code.?);
    try std.testing.expectEqual(@as(u8, 0), res.version.?);
    try std.testing.expectEqual(@as(usize, 1), res.headers.len);
    try std.testing.expectEqualStrings("Server", res.headers[0].name);
    try std.testing.expectEqualStrings("foo.bar", res.headers[0].value);
}

test "response missing reason" {
    const header = "HTTP/1.0 403 \r\n\r\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 403), res.code.?);
    try std.testing.expectEqual(@as(u8, 0), res.version.?);
}

test "response missing reason without space" {
    const header = "HTTP/1.0 403\r\n\r\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 403), res.code.?);
    try std.testing.expectEqual(@as(u8, 0), res.version.?);
}

test "response missing reason with header" {
    const header = "HTTP/1.1 403\r\nServer: foo.bar\r\n\r\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 403), res.code.?);
    try std.testing.expectEqual(@as(u8, 1), res.version.?);
    try std.testing.expectEqual(@as(usize, 1), res.headers.len);
    try std.testing.expectEqualStrings("Server", res.headers[0].name);
    try std.testing.expectEqualStrings("foo.bar", res.headers[0].value);
}

test "response reason with space and tab" {
    const header = "HTTP/1.1 101 Switching Protocols\t\r\n\r\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 101), res.code.?);
    try std.testing.expectEqual(@as(u8, 1), res.version.?);
}

test "response reason with obsolete text byte" {
    const header = "HTTP/1.1 200 X\xFFZ\r\n\r\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 200), res.code.?);
    try std.testing.expectEqual(@as(u8, 1), res.version.?);
    try std.testing.expectEqual(@as(usize, 0), res.headers.len);
}

test "response reason with nul byte" {
    const header = "HTTP/1.1 200 \x00\r\n\r\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 200), res.code.?);
    try std.testing.expectEqual(@as(u8, 1), res.version.?);
    try std.testing.expectEqual(@as(usize, 0), res.headers.len);
}

test "response missing version space" {
    const header = "HTTP/1.1";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);

    try std.testing.expectError(ParseError.Eof, res.parse(header));
}

test "response missing code space" {
    const header = "HTTP/1.1 200";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);

    try std.testing.expectError(ParseError.Eof, res.parse(header));
}

test "response empty line prefix" {
    const header = "\n\nHTTP/1.1 200 OK\n\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 200), res.code.?);
    try std.testing.expectEqual(@as(u8, 1), res.version.?);
    try std.testing.expectEqual(@as(usize, 0), res.headers.len);
}

test "response no cr" {
    const header = "HTTP/1.0 200\nContent-type: text/html\n\n";
    var headers: [10]Header = undefined;
    var res = Response.init(&headers);
    try res.parse(header);

    try std.testing.expectEqual(@as(u16, 200), res.code.?);
    try std.testing.expectEqual(@as(u8, 0), res.version.?);
    try std.testing.expectEqual(@as(usize, 1), res.headers.len);
    try std.testing.expectEqualStrings("Content-type", res.headers[0].name);
    try std.testing.expectEqualStrings("text/html", res.headers[0].value);
}

test "chunk size" {
    var value = try parseChunkSize("0\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 0), value.len);
    try std.testing.expectEqual(@as(usize, 3), value.pos);

    value = try parseChunkSize("12\r\nchunk"[0..]);
    try std.testing.expectEqual(@as(u64, 18), value.len);
    try std.testing.expectEqual(@as(usize, 4), value.pos);

    value = try parseChunkSize("3086d\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 198765), value.len);
    try std.testing.expectEqual(@as(usize, 7), value.pos);

    value = try parseChunkSize("3735AB1;foo bar*\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 57891505), value.len);
    try std.testing.expectEqual(@as(usize, 18), value.pos);

    value = try parseChunkSize("3735ab1 ; baz \r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 57891505), value.len);
    try std.testing.expectEqual(@as(usize, 16), value.pos);

    value = try parseChunkSize("ffffffffffffffff\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 18446744073709551615), value.len);
    try std.testing.expectEqual(@as(usize, 18), value.pos);

    try std.testing.expectError(ParseError.Eof, parseChunkSize("77a65\r"[0..]));
    try std.testing.expectError(ParseError.Eof, parseChunkSize("ab"[0..]));
    try std.testing.expectError(ParseError.InvalidChunkSize, parseChunkSize("567f8a\rfoo"[0..]));
    try std.testing.expectError(ParseError.InvalidChunkSize, parseChunkSize("567xf8a\r\n"[0..]));
    try std.testing.expectError(ParseError.InvalidChunkSize, parseChunkSize("1ffffffffffffffff\r\n"[0..]));
    try std.testing.expectError(ParseError.InvalidChunkSize, parseChunkSize("Affffffffffffffff\r\n"[0..]));
    try std.testing.expectError(ParseError.InvalidChunkSize, parseChunkSize("fffffffffffffffff\r\n"[0..]));

    value = try parseChunkSize("012\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 18), value.len);
    try std.testing.expectEqual(@as(usize, 5), value.pos);

    value = try parseChunkSize("00\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 0), value.len);
    try std.testing.expectEqual(@as(usize, 4), value.pos);

    value = try parseChunkSize("a\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 3), value.pos);

    value = try parseChunkSize("A\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 3), value.pos);

    value = try parseChunkSize("Ff\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 255), value.len);
    try std.testing.expectEqual(@as(usize, 4), value.pos);

    value = try parseChunkSize("fF   \r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 255), value.len);
    try std.testing.expectEqual(@as(usize, 7), value.pos);

    value = try parseChunkSize("1;baz\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 1), value.len);
    try std.testing.expectEqual(@as(usize, 7), value.pos);

    value = try parseChunkSize("a;ext name=value\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 18), value.pos);

    value = try parseChunkSize("a;ext1;ext2\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 13), value.pos);

    value = try parseChunkSize("a;; ;\t;\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 9), value.pos);

    value = try parseChunkSize("a; ext...\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 11), value.pos);

    value = try parseChunkSize("a   ;   ext=Af   \r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 19), value.pos);

    value = try parseChunkSize("a   ;\r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 7), value.pos);

    value = try parseChunkSize("a   ;      \r\n"[0..]);
    try std.testing.expectEqual(@as(u64, 10), value.len);
    try std.testing.expectEqual(@as(usize, 13), value.pos);

    try std.testing.expectError(ParseError.InvalidChunkSize, parseChunkSize("1K\r\n"[0..]));
    try std.testing.expectError(ParseError.Eof, parseChunkSize("1;no crlf"[0..]));
}
