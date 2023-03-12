const std = @import("std");
const httpparser = @import("httpparser");

// Request and Response copy from rust httparse.
const LONG_REQ =
    "GET /wp-content/uploads/2010/03/hello-kitty-darth-vader-pink.jpg HTTP/1.1\r\n" ++
    "Host: www.kittyhell.com\r\n" ++
    "User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; ja-JP-mac; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 Pathtraq/0.9\r\n" ++
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" ++
    "Accept-Language: ja,en-us;q=0.7,en;q=0.3\r\n" ++
    "Accept-Encoding: gzip,deflate\r\n" ++
    "Accept-Charset: Shift_JIS,utf-8;q=0.7,*;q=0.7\r\n" ++
    "Keep-Alive: 115\r\n" ++
    "Connection: keep-alive\r\n" ++
    "Cookie: wp_ozh_wsa_visits=2; wp_ozh_wsa_visit_lasttime=xxxxxxxxxx; __utma=xxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.x; __utmz=xxxxxxxxx.xxxxxxxxxx.x.x.utmccn=(referral)|utmcsr=reader.livedoor.com|utmcct=/reader/|utmcmd=referral|padding=under256\r\n\r\n";

const SHORT_REQ =
    "GET / HTTP/1.0\r\n" ++
    "Host: example.com\r\n" ++
    "Cookie: session=60; user_id=1\r\n\r\n";

const SHORT_RESP =
    "HTTP/1.0 200 OK\r\n" ++
    "Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n" ++
    "Set-Cookie: session=60; user_id=1\r\n\r\n";

const LONG_RESP =
    "HTTP/1.1 200 OK\r\n" ++
    "Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n" ++
    "Host: www.kittyhell.com\r\n" ++
    "User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; ja-JP-mac; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 Pathtraq/0.9\r\n" ++
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" ++
    "Accept-Language: ja,en-us;q=0.7,en;q=0.3\r\n" ++
    "Accept-Encoding: gzip,deflate\r\n" ++
    "Accept-Charset: Shift_JIS,utf-8;q=0.7,*;q=0.7\r\nv" ++
    "Keep-Alive: 115\r\n" ++
    "Connection: keep-alive\r\n" ++
    "Cookie: wp_ozh_wsa_visits=2; wp_ozh_wsa_visit_lasttime=xxxxxxxxxx; __utma=xxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.xxxxxxxxxx.x; __utmz=xxxxxxxxx.xxxxxxxxxx.x.x.utmccn=(referral)|utmcsr=reader.livedoor.com|utmcct=/reader/|utmcmd=referral|padding=under256\r\n\r\n";

const max_iteration: u32 = 10_000_000;

fn runRequest(payload: []const u8, name: []const u8) !void {
    var headers: [32]httpparser.Header = undefined;
    var i: usize = 0;
    const start_time = std.time.milliTimestamp();
    while (i < max_iteration) : (i += 1) {
        var req = httpparser.Request.init(&headers);
        try req.parse(payload);
    }
    const end_time = std.time.milliTimestamp();
    const s = @intToFloat(f64, (end_time - start_time)) / 1_000;
    const mb = @intToFloat(f64, payload.len * max_iteration) / 1_000_000;
    std.log.info("{s}: {d:0>1.2}mb/{d:0>1.3}s = {d:0>1.2}mbps", .{ name, mb, s, (mb / s) });
}

fn runResponse(payload: []const u8, name: []const u8) !void {
    var headers: [32]httpparser.Header = undefined;
    var i: usize = 0;
    const start_time = std.time.milliTimestamp();
    while (i < max_iteration) : (i += 1) {
        var req = httpparser.Response.init(&headers);
        try req.parse(payload);
    }
    const end_time = std.time.milliTimestamp();
    const s = @intToFloat(f64, (end_time - start_time)) / 1_000;
    const mb = @intToFloat(f64, payload.len * max_iteration) / 1_000_000;
    std.log.info("{s}: {d:0>1.2}mb/{d:0>1.3}s = {d:0>1.2}mbps", .{ name, mb, s, (mb / s) });
}

pub fn main() !void {
    try runRequest(LONG_REQ, "Long req");
    try runRequest(SHORT_REQ, "Short req");
    try runResponse(LONG_RESP, "Long resp");
    try runResponse(SHORT_RESP, "Short resp");
}
