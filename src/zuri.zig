const std = @import("std");
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;


const StringList = ArrayList([]const u8);
const ValueMap = AutoHashMap([]const u8, []const u8);

const URI = struct {
    raw: []const u8,
    scheme: []const u8,
    authority: Authority,
    
    const Authority = struct {
        username: []const u8,
        password: []const u8,
        host: []const u8,
        port: u16,
    }

    path: [][]const u8,
    query: []const u8,
    fragment: []const u8,

    pub fn mapQuery(self: *URI, allocator: *Allocator) !ValueMap {

    }
};



const State = enum {
    Scheme,
    Auth,
    AuthColon,
    IPV6,
    Host,
    Port,
    Path,
    Query,
    Fragment,
}

pub fn parse(allocator: *Allocator. input: []) !URI {
    var state: State = .Scheme;

}
