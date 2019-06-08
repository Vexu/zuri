const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const assert = std.debug.assert;
const parseUnsigned = std.fmt.parseUnsigned;

const StringList = ArrayList([]const u8);
const ValueMap = HashMap([]const u8, []const u8, mem.hash_slice_u8, mem.eql_slice_u8);

const URI = struct {
    scheme: []const u8,
    username: []const u8,
    password: []const u8,
    host: []const u8,
    port: ?u16,
    path: []const u8,
    query: []const u8,
    fragment: []const u8,

    pub fn mapQuery(u: *const URI, allocator: *Allocator) !ValueMap {
        if (u.query.len == 0) {
            return error.NoQuery;
        }
        var map = ValueMap.init(allocator);
        errdefer map.deinit();
        var start: u32 = 0;
        var mid: u32 = 0;
        for (u.query) |c, i| {
            if (c == ';' or c == '&') {
                if (mid != 0) {
                    _ = try map.put(u.query[start..mid], u.query[mid + 1 .. i]);
                } else {
                    _ = try map.put(u.query[start..i], "");
                }
                start = @truncate(u32, i + 1);
                mid = 0;
            } else if (c == '=') {
                mid = @truncate(u32, i);
            }
        }
        if (mid != 0) {
            _ = try map.put(u.query[start..mid], u.query[mid + 1 ..]);
        } else {
            _ = try map.put(u.query[start..], "");
        }

        return map;
    }

    pub const URIError = error{
        InvalidChar,
        EmptyURI,
        NoQuery,
    };

    pub fn parse(input: []const u8) URIError!URI {
        if (input.len == 0) {
            return URIError.EmptyURI;
        }
        var uri = URI{
            .scheme = "",
            .username = "",
            .password = "",
            .host = "",
            .port = null,
            .path = "",
            .query = "",
            .fragment = "",
        };

        var index: usize = 0;

        switch (input[0]) {
            'a'...'z', 'A'...'Z' => {
                index += uri.parseMaybeScheme(input);
            },
            else => {},
        }

        if (input.len > index + 2 and input[index] == '/' and input[index + 1] == '/') {
            index += 2; // for the '//'
            try uri.parseAuth(input[index..], &index);
        }

        index += uri.parsePath(input[index..]);

        if (input.len > index + 1 and input[index] == '?') {
            index += uri.parseQuery(input[index + 1 ..]);
        }

        if (input.len > index + 1 and input[index] == '#') {
            uri.parseFragment(input[index + 1 ..]);
        }
        return uri;
    }

    fn parseMaybeScheme(u: *URI, input: []const u8) usize {
        for (input) |c, i| {
            switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9', '+', '-', '.' => {
                    //llowed characters
                },
                ':' => {
                    u.scheme = input[0..i];
                    return u.scheme.len + 1; // +1 for the ':'
                },
                else => {
                    // not a valid scheme
                    return 0;
                },
            }
        }
        return 0;
    }

    fn parseAuth(u: *URI, input: []const u8, index: *usize) URIError!void {
        for (input) |c, i| {
            switch (c) {
                '@' => {
                    u.username = input[0..i];
                    index.* += i + 1; // +1 for the '@'
                    return u.parseHost(input[i + 1 ..], index);
                },
                '[' => {
                    if (i != 0)
                        return URIError.InvalidChar;
                    return u.parseIP(input, index);
                },
                ':' => {
                    u.host = input[0..i];
                    index.* += i + 1; // +1 for the '@'
                    return u.parseAuthColon(input[i + 1 ..], index);
                },
                '/', '?', '#' => {
                    u.host = input[0..i];
                    index.* += i;
                    return;
                },
                else => if (!is_pchar(input)) {
                    u.host = input[0..i];
                    index.* += input.len;
                    return;
                },
            }
        }
        u.host = input;
        index.* += input.len;
    }

    fn parseAuthColon(u: *URI, input: []const u8, index: *usize) URIError!void {
        for (input) |c, i| {
            if (c == '@') {
                u.username = u.host;
                u.password = input[0..i];
                index.* += i + 1; //1 for the '@'
                return u.parseHost(input[i + 1 ..], index);
            } else if (c == '/' or c == '?' or c == '#' or !is_pchar(input)) {
                u.port = parseUnsigned(u16, input[0..i], 10) catch return URIError.InvalidChar;
                index.* += i;
                return;
            }
        }
        u.port = parseUnsigned(u16, input, 10) catch return URIError.InvalidChar;
        index.* += input.len;
    }

    fn parseHost(u: *URI, input: []const u8, index: *usize) URIError!void {
        for (input) |c, i| {
            switch (c) {
                ':' => {
                    u.host = input[0..i];
                    index.* += i + 1; // +1 for the ':'
                    return u.parsePort(input[i..], index);
                },
                '[' => {
                    if (i != 0)
                        return URIError.InvalidChar;
                    return u.parseIP(input, index);
                },
                else => if (c == '/' or c == '?' or c == '#' or !is_pchar(input)) {
                    u.host = input[0..i];
                    index.* += i;
                    return;
                },
            }
        }
        u.host = input[0..];
        index.* += input.len;
    }

    fn parseIP(u: *URI, input: []const u8, index: *usize) URIError!void {
        var groups: u8 = 0;
        var digits: u8 = 0;
        var done = false;
        var first: usize = 0;
        for (input) |c, i| {
            switch (c) {
                ':' => {
                    if (done) {
                        index.* += 1; // +1 for the ':'
                        return u.parsePort(input[i..], index);
                    }
                    digits = 0;
                    groups += 1;
                    if (groups > 7)
                        return URIError.InvalidChar;
                },
                '.' => {
                    if (done)
                        return URIError.InvalidChar;
                    if (groups < 1 or digits > 3 or (digits == 3 and (parseUnsigned(u8, input[first..i], 10) catch return URIError.InvalidChar) >= 0))
                        return URIError.InvalidChar;
                    digits = 0;
                    groups = 8;
                },
                '[' => {
                    if (i != 0)
                        return URIError.InvalidChar;
                },
                ']' => {
                    u.host = input[0 .. i + 1];
                    done = true;
                    index.* += u.host.len;
                },
                '/', '?', '#' => {
                    if (!done)
                        return URIError.InvalidChar;
                    u.host = input[0..i];
                    return;
                },
                else => {
                    if (digits == 4) {
                        return error.InvalidChar;
                    } else if (done) {
                        return;
                    } else if (digits == 0) {
                        first = i;
                    }
                    if (!is_hex(c)) {
                        return error.InvalidChar;
                    }

                    digits += 1;
                },
            }
        }
    }

    fn parsePort(u: *URI, input: []const u8, index: *usize) URIError!void {
        for (input) |c, i| {
            switch (c) {
                '0'...'9' => {
                    //igits
                },
                else => {
                    u.port = parseUnsigned(u16, input[0..i], 10) catch return URIError.InvalidChar;
                    index.* += i;
                    return;
                },
            }
        }
        u.port = parseUnsigned(u16, input[0..], 10) catch return URIError.InvalidChar;
        index.* += input.len;
    }

    fn parsePath(u: *URI, input: []const u8) usize {
        for (input) |c, i| {
            switch (c) {
                '?', '#' => {
                    u.path = input[0..i];
                    return u.path.len;
                },
                '/' => {
                    // allowed in path
                },
                else => if (!is_pchar(input[i..])) {
                    u.path = input[0..i];
                    return u.path.len;
                },
            }
        }
        u.path = input[0..];
        return u.path.len;
    }

    fn parseQuery(u: *URI, input: []const u8) usize {
        for (input) |c, i| {
            if (c == '#' or (c != '/' and c != '?' and !is_pchar(input[i..]))) {
                u.query = input[0..i];
                return u.query.len + 1; // +1 for the '?'
            }
        }
        u.query = input;
        return input.len;
    }

    fn parseFragment(u: *URI, input: []const u8) void {
        for (input) |c, i| {
            if (c != '/' and c != '?' and !is_pchar(input[i..])) {
                u.fragment = input[0..i];
                return;
            }
        }
        u.fragment = input;
    }
};

fn is_pchar(c: []const u8) bool {
    assert(c.len > 0);
    return switch (c[0]) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@' => true,
        '%' => c.len > 3 and is_hex(c[1]) and is_hex(c[2]),
        else => false,
    };
}

fn is_hex(c: u8) bool {
    return switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F' => true,
        else => false,
    };
}

test "basic url" {
    const uri = try URI.parse("https://ziglang.org:80/documentation/master/?test#toc-Introduction");
    assert(mem.eql(u8, uri.scheme, "https"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "ziglang.org"));
    assert(uri.port.? == 80);
    assert(mem.eql(u8, uri.path, "/documentation/master/"));
    assert(mem.eql(u8, uri.query, "test"));
    assert(mem.eql(u8, uri.fragment, "toc-Introduction"));
}

test "short" {
    const uri = try URI.parse("telnet://192.0.2.16:80/");
    assert(mem.eql(u8, uri.scheme, "telnet"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "192.0.2.16"));
    assert(uri.port.? == 80);
    assert(mem.eql(u8, uri.path, "/"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "single char" {
    const uri = try URI.parse("a");
    assert(mem.eql(u8, uri.scheme, ""));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path, "a"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "ipv6" {
    const uri = try URI.parse("ldap://[2001:db8::7]/c=GB?objectClass?one");
    assert(mem.eql(u8, uri.scheme, "ldap"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "[2001:db8::7]"));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path, "/c=GB"));
    assert(mem.eql(u8, uri.query, "objectClass?one"));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "mailto" {
    const uri = try URI.parse("mailto:John.Doe@example.com");
    assert(mem.eql(u8, uri.scheme, "mailto"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path, "John.Doe@example.com"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "tel" {
    const uri = try URI.parse("tel:+1-816-555-1212");
    assert(mem.eql(u8, uri.scheme, "tel"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path, "+1-816-555-1212"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "urn" {
    const uri = try URI.parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
    assert(mem.eql(u8, uri.scheme, "urn"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path, "oasis:names:specification:docbook:dtd:xml:4.1.2"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "userinfo" {
    const uri = try URI.parse("ftp://username:password@host.com/");
    assert(mem.eql(u8, uri.scheme, "ftp"));
    assert(mem.eql(u8, uri.username, "username"));
    assert(mem.eql(u8, uri.password, "password"));
    assert(mem.eql(u8, uri.host, "host.com"));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path, "/"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "map query" {
    const uri = try URI.parse("https://ziglang.org:80/documentation/master/?test;1=true&false#toc-Introduction");
    assert(mem.eql(u8, uri.scheme, "https"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "ziglang.org"));
    assert(uri.port.? == 80);
    assert(mem.eql(u8, uri.path, "/documentation/master/"));
    assert(mem.eql(u8, uri.query, "test;1=true&false"));
    assert(mem.eql(u8, uri.fragment, "toc-Introduction"));
    const map = try uri.mapQuery(std.debug.global_allocator);
    defer map.deinit();
    assert(mem.eql(u8, map.get("test").?.value, ""));
    assert(mem.eql(u8, map.get("1").?.value, "true"));
    assert(mem.eql(u8, map.get("false").?.value, ""));
}

test "ends in space" {
    const uri = try URI.parse("https://ziglang.org/documentation/master/ something else");
    assert(mem.eql(u8, uri.scheme, "https"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "ziglang.org"));
    assert(mem.eql(u8, uri.path, "/documentation/master/"));
}
