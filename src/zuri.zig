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

pub fn parse(allocator: *Allocator, input: []const u8) !URI {
    var state: State = .Begin;
    var tok_begin: usize = 0;
    var path_list = StringList.init(allocator);
    defer path_list.deinit();

    var uri = URI{
        .scheme = "",
        .username = "",
        .password = "",
        .host = "",
        .port = null,
        .path = undefined,
        .query = "",
        .fragment = "",
    };

    for (input) |c, i| {
        switch (state) {
            .Begin => switch (c) {
                '/' => {
                    state = .PathOrAuth;
                },
                'a' ... 'z', 'A'...'Z' => {
                    state = .MaybeScheme;
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                    state = .Path;
                },
            },
            .PathOrAuth => switch(c) {
                '/' => {
                    state = .Auth;
                    tok_begin = i+1;
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                    state = .Path;
                },
            },
            .MaybeScheme => switch (c) {
                'a' ... 'z', 'A'...'Z', '0'...'9', '+', '-', '.' => {
                    //allowed characters
                },
                ':' => {
                    uri.scheme = input[tok_begin..i];
                    state = .AfterScheme;
                    tok_begin = i + 1;
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                    state = .Path;
                },
            },
            .AfterScheme => switch (c) {
                '/' => {
                    state = .PathOrAuth;
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                    state = .Path;
                },
            },
            .Auth => switch(c) {
                '@' => {
                    state = .Host;
                    uri.username = input[tok_begin..i];
                    tok_begin = i+1;
                },
                '[' => {
                    state = .IPV6;
                    tok_begin = i+1;
                },
                ':' => {
                    state = .AuthColon;
                    uri.host = input[tok_begin..i];
                    tok_begin = i+1;
                },
                '/', '?', '#' => {
                    uri.host = input[tok_begin..i];
                    switch (c) {
                        '/' => {
                            state = .Path;
                            tok_begin = i;
                        },
                        '?' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        '#' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        else => unreachable,
                    }
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            },
            .AuthColon => switch(c) {
                '@' => {
                    state = .Host;
                    uri.username = uri.host;
                    uri.password = input[tok_begin..i];
                    tok_begin = i+1;
                },
                '/', '?', '#' => {
                    uri.port = try parseUnsigned(u16, input[tok_begin..i], 10);
                    switch (c) {
                        '/' => {
                            state = .Path;
                            tok_begin = i;
                        },
                        '?' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        '#' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        else => unreachable,
                    }
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            },
            .Host => switch(c) {
                ':' => {
                    state = .Port;
                    uri.host = input[tok_begin..i];
                    tok_begin = i+1;
                },
                '[' => {
                    state = .IPV6;
                    tok_begin = i+1;
                },
                '/', '?', '#' => {
                    uri.host = input[tok_begin..i];
                    switch (c) {
                        '/' => {
                            state = .Path;
                            tok_begin = i;
                        },
                        '?' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        '#' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        else => unreachable,
                    }
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                }
            },

            .IPV6 => switch(c) {//todo
                '/', '?', '#' => {
                    switch (c) {
                        '/' => {
                            state = .Path;
                            tok_begin = i;
                        },
                        '?' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        '#' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        else => unreachable,
                    }
                },
                else => {

                }
            },
            .IPV6Cont => {

            },


            .Port => switch(c) {
                '0'...'9' => {
                    //digits
                },
                '/', '?', '#' => {
                    uri.port = try parseUnsigned(u16, input[tok_begin..i], 10);
                    switch (c) {
                        '/' => {
                            state = .Path;
                            tok_begin = i;
                        },
                        '?' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        '#' => {
                            state = .Path;
                            tok_begin = i+1;
                        },
                        else => unreachable,
                    }
                },
                else => return error.InvalidChar,
            },
            .Path => switch(c) {
                '?' => {
                    state = .Query;
                    try path_list.append(input[tok_begin..i]);
                    tok_begin = i+1;
                },
                '#' => {
                    state = .Fragment;
                    try path_list.append(input[tok_begin..i]);
                    tok_begin = i+1;
                },
                '/' => {
                    try path_list.append(input[tok_begin..i]);
                    tok_begin = i;
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                },
            },
            .Query => switch(c) {
                '#' => {
                    state = .Fragment;
                    uri.query = input[tok_begin..i];
                    tok_begin = i+1;
                },
                '/', '?' => {
                    //allowed
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                },
            },
            .Fragment => switch(c) {
                '/', '?' => {
                    //allowed
                },
                else => {
                    if (!is_pchar(input))
                        return error.InvalidChar;
                },
            },
        }
    }
    switch (state) {
        .Fragment => uri.fragment = input[tok_begin..],
        .Query => uri.query = input[tok_begin..],
        else => std.debug.panic("unimplemented finalizer {}", state),
    }
    uri.path = path_list.toOwnedSlice();
    return uri;
}

fn is_pchar(c: []const u8) bool {
    assert(c.len > 1);
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
    const uri = try parse(std.debug.global_allocator, "https://ziglang.org/documentation/master/?test#toc-Introduction");
    assert(mem.eql(u8, uri.scheme, "https"));
    assert(mem.eql(u8, uri.username, ""));
    assert(mem.eql(u8, uri.password, ""));
    assert(mem.eql(u8, uri.host, "ziglang.org"));
    assert(uri.port == null);
    assert(mem.eql(u8, uri.path[0], "/documentation"));
    assert(mem.eql(u8, uri.path[1], "/master"));
    assert(mem.eql(u8, uri.path[2], "/"));
    assert(mem.eql(u8, uri.query, "test"));
    assert(mem.eql(u8, uri.fragment, "toc-Introduction"));
}