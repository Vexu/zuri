const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;
const assert = std.debug.assert;
const parseUnsigned = std.fmt.parseUnsigned;


const StringList = ArrayList([]const u8);
const ValueMap = AutoHashMap([]const u8, []const u8);

const URI = struct {
    scheme: []const u8,
    username: []const u8,
    password: []const u8,
    host: []const u8,
    port: ?u16,
    path: [][]const u8,
    query: []const u8,
    fragment: []const u8,

    pub fn mapQuery(self: *URI, allocator: *Allocator) !ValueMap {

    }
};

const URIError = error {
    InvalidChar,
    EmptyURI,
};

const State = enum {
    Begin,
    PathOrAuth,

    MaybeScheme,
    AfterScheme,
    Auth,
    AuthColon,
    
    IPV6,
    IPV6Cont,
    Host,
    Port,

    Path,

    Query,
    Fragment,
};

pub const Parser = struct {
    path_list: StringList,
    uri: *URI,

    pub fn init(allocator: *Allocator) Parser {
        return Parser{
            .path_list = StringList.init(allocator),
            .uri = undefined,
        };
    }
    
    pub fn deinit(p: *Parser) void {
        p.path_list.deinit();
    }

    pub fn parse(p: *Parser, input: []const u8) !URI {
        if (input.len == 0)
            return error.EmptyURI;
        var uri = URI{
            .scheme = "",
            .username = "",
            .password = "",
            .host = "",
            .port = null,
            .path = [][]const u8 {},
            .query = "",
            .fragment = "",
        };
        p.uri = &uri;

        switch (input[0]) {
            '/' => {
                if (input.len > 1 and input[1] == '/') {
                    try p.parseAuth(input[2..]);
                } else if (is_pchar(input[1..])) {
                    try p.parsePath(input);
                } else {
                    return error.InvalidChar;
                }
            },
            'a' ... 'z', 'A'...'Z' => {
                try p.parseMaybeScheme(input);
            },
            else => {
                if (!is_pchar(input))
                    return error.InvalidChar;
                try p.parsePath(input);
            }
        }

        p.uri.path = p.path_list.toOwnedSlice();
        return uri;
    }

    pub fn parseMaybeScheme(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            switch (c) {
                'a' ... 'z', 'A'...'Z', '0'...'9', '+', '-', '.' => {
                    //allowed characters
                },
                ':' => {
                    p.uri.scheme = input[0..i];
                    if (input.len > i + 1) {
                        if (input[i+1] == '/') {
                            if (input.len > i + 2 and input[i+2] == '/') {
                                return p.parseAuth(input[i+3..]);
                            }
                            return p.parsePath(input[i+1..]);
                        } else {
                            return p.parseMaybeAuth(input[i+1..]);
                        }
                    } else {
                        return;
                    }
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                },
            }
        }
        try p.path_list.append(input);
    }

    fn parseMaybeAuth(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            switch (c) {
                '[' => {
                    if (i != 0)
                        return error.InvalidChar;
                    return p.parseIP(input);
                },
                '/', '?', '#' => {
                    try p.path_list.append(input[0..i]);
                    return p.parsePath(input[i..]);
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            }
        }
        try p.path_list.append(input[0..]);
    }

    fn parseAuth(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            switch (c) {
                '@' => {
                    p.uri.username = input[0..i];
                    return p.parseHost(input[i+1..]);
                },
                '[' => {
                    if (i != 0)
                        return error.InvalidChar;
                    return p.parseIP(input);
                },
                ':' => {
                    p.uri.host = input[0..i];
                    return p.parseAuthColon(input[i+1..]);
                },
                '/', '?', '#' => {
                    p.uri.host = input[0..i];
                    return p.parsePath(input[i..]);
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            }
        }
        p.uri.host = input;
    }

    fn parseAuthColon(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            switch (c) {
                '@' => {
                    p.uri.username = p.uri.host;
                    p.uri.password = input[0..i];
                    return p.parseHost(input[i+1..]);
                },
                '/', '?', '#' => {
                    p.uri.port = try parseUnsigned(u16, input[0..i], 10);
                    return p.parsePath(input[i..]);
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            }
        }
        p.uri.port = try parseUnsigned(u16, input, 10);
    }

    fn parseHost(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            switch (c) {
                ':' => {
                    return p.parsePort(input[i..]);
                },
                '[' => {
                    if (i != 0)
                        return error.InvalidChar;
                    return p.parseIP(input);
                },
                '/', '?', '#' => {
                    p.uri.host = input[0..i];
                    return p.parsePath(input[i..]);
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            }
        }
        p.uri.host = input[0..];
    }

    fn parseIP(p: *Parser, input: []const u8) !void {
        // unreachable;
        return error.InvalidChar;
    }

    fn parsePort(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            switch (c) {
                '0'...'9' => {
                    //digits
                },
                '/', '?', '#' => {
                    p.uri.port = try parseUnsigned(u16, input[0..i], 10);
                    return p.parsePath(input[i..]);
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            }
        }
        p.uri.port = try parseUnsigned(u16, input[0..], 10);
    }
    
    fn parsePath(p: *Parser, input: []const u8) !void {
        const uri = p.uri;

        var begin: usize = 0;
        for (input) |c, i| {
            switch (c) {
                '?' => {
                    if (begin != i)
                        try p.path_list.append(input[begin..i]);
                    return p.parseQuery(input[i+1..]);
                },
                '#' => {
                    if (begin != i)
                        try p.path_list.append(input[begin..i]);
                    return p.parseFragment(input[i+1..]);
                },
                '/' => {
                    if (begin != i)
                        try p.path_list.append(input[begin..i]);
                    begin = i;
                },
                '.' => {
                    //todo
                    unreachable;
                },
                else => {
                    if (!is_pchar(input[i..]))
                        return error.InvalidChar;
                },
            }
        }
        try p.path_list.append(input[begin..]);
    }

    fn parseQuery(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            if (c == '#') {
                p.uri.query = input[0..i];
                return p.parseFragment(input[i+1..]);
            } else if (c != '/' and c != '?' and !is_pchar(input[i..])) {
                        return error.InvalidChar;
            }
        }
        p.uri.query = input;
    }

    fn parseFragment(p: *Parser, input: []const u8) !void {
        for (input) |c, i| {
            if (c != '/' and c != '?' and !is_pchar(input[i..]) ) {
                return error.InvalidChar;
            }
        }
        p.uri.fragment = input;
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
    var p = Parser.init(std.debug.global_allocator);
    defer p.deinit();
    const uri = try p.parse("https://ziglang.org:80/documentation/master/?test#toc-Introduction");
    assert(mem.eql(u8, uri.scheme, "https"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "ziglang.org"));
    assert(uri.port.? == 80);
    assert(mem.eql(u8, uri.path[0], "/documentation"));
    assert(mem.eql(u8, uri.path[1], "/master"));
    assert(mem.eql(u8, uri.path[2], "/"));
    assert(mem.eql(u8, uri.query, "test"));
    assert(mem.eql(u8, uri.fragment, "toc-Introduction"));
}

test "short" {
    var p = Parser.init(std.debug.global_allocator);
    defer p.deinit();
    const uri = try p.parse("telnet://192.0.2.16:80/");
    assert(mem.eql(u8, uri.scheme, "telnet"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "192.0.2.16"));
    assert(uri.port.? == 80);
    assert(mem.eql(u8, uri.path[0], "/"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "single char" {
    var p = Parser.init(std.debug.global_allocator);
    defer p.deinit();
    const uri = try p.parse("a");
    assert(mem.eql(u8, uri.scheme, ""));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path[0], "a"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

// test "ipv6" {//todo
//     var p = Parser.init(std.debug.global_allocator);
//     defer p.deinit();
//     const uri = try p.parse("ldap://[2001:db8::7]/c=GB?objectClass?one");
//     assert(mem.eql(u8, uri.scheme, "ldap"));
//     assert(mem.eql(u8, uri.username, ""));
//     assert(mem.eql(u8, uri.password, ""));
//     assert(mem.eql(u8, uri.host, "[2001:db8::7]"));
//     assert(uri.port == null);
//     assert(mem.eql(u8, uri.path[0], "/c=GB"));
//     assert(mem.eql(u8, uri.query, "objectClass?one"));
//     assert(mem.eql(u8, uri.fragment, ""));
// }

test "mailto" {
    var p = Parser.init(std.debug.global_allocator);
    defer p.deinit();
    const uri = try p.parse("mailto:John.Doe@example.com");
    assert(mem.eql(u8, uri.scheme, "mailto"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path[0], "John.Doe@example.com"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "tel" {
    var p = Parser.init(std.debug.global_allocator);
    defer p.deinit();
    const uri = try p.parse("tel:+1-816-555-1212");
    assert(mem.eql(u8, uri.scheme, "tel"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path[0], "+1-816-555-1212"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "urn" {
    var p = Parser.init(std.debug.global_allocator);
    defer p.deinit();
    const uri = try p.parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2");
    assert(mem.eql(u8, uri.scheme, "urn"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, ""));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path[0], "oasis:names:specification:docbook:dtd:xml:4.1.2"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}

test "userinfo" {
    var p = Parser.init(std.debug.global_allocator);
    defer p.deinit();
    const uri = try p.parse("ftp://username:password@host.com/");
    assert(mem.eql(u8, uri.scheme, "ftp"));
    assert(mem.eql(u8, uri.username, "username"));
    assert(mem.eql(u8, uri.password, "password"));
    assert(mem.eql(u8, uri.host, "host.com"));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path[0], "/"));
    assert(mem.eql(u8, uri.query, ""));
    assert(mem.eql(u8, uri.fragment, ""));
}