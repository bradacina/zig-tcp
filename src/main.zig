const std = @import("std");
const windows = std.os.windows;
const alloc = std.mem.Allocator;
const mem = std.mem;

const ip = @cImport({
    @cInclude("winsock2.h");
    @cInclude("ws2tcpip.h");
    @cInclude("iphlpapi.h");
});

const row = struct { remoteAddr: [15:0]u8 = [_:0]u8{0} ** 15, localAddr: [15:0]u8 = [_:0]u8{0} ** 15, remotePort: u32 = 0, localPort: u32 = 0 };

// pub extern "iphlpapi" fn GetTcpTable2(tcptable: ip.PMIB_TCPTABLE2, size: *windows.ULONG, order: windows.BOOL) windows.ULONG;
// pub extern "user32" fn MessageBoxA(hWnd: ?windows.HWND, lpText: windows.LPCSTR, lpCaption: windows.LPCSTR, uType: windows.UINT) c_int;

// pub fn wWinMain(hInstance: windows.HINSTANCE, _: ?windows.HINSTANCE, lpCmdLine: windows.LPWSTR, nShowCmd: c_int) c_int {
//     // this is here just to make the zig compiler happy
//     return 0;
// }

// pub export fn WinMain(hInstance: windows.HINSTANCE, _: ?windows.HINSTANCE, lpCmdLine: windows.LPWSTR, nShowCmd: c_int) c_int {
//     _ = MessageBoxA(null, "hello", "alive", 0);
//     return 0;
// }

pub fn main() !void {
    var len: u32 = 2000;
    const allocator: *mem.Allocator = std.heap.page_allocator;
    const buffer = try allocator.allocAdvanced(u8, @alignOf(ip.MIB_TCPTABLE2), len, alloc.Exact.exact);
    const tablePointer = @ptrCast(ip.PMIB_TCPTABLE2, buffer);

    const res = ip.GetTcpTable2(tablePointer, &len, windows.TRUE);
    std.log.info("Result {}, Length {}", .{ res, len });

    var numEntries = tablePointer.*.dwNumEntries;
    var table = @ptrCast([*]ip.MIB_TCPROW2, &tablePointer.*.table);

    var i: usize = 0;
    var results: []row = try allocator.alloc(row, numEntries);
    while (i < numEntries) : (i += 1) {
        results[i] = toRow(table[i]);
    }
}

fn toRow(from: ip.MIB_TCPROW2) row {
    var addr: ip.in_addr = ip.in_addr{ .S_un = .{ .S_addr = 0 } };
    var result = row{};

    addr.S_un.S_addr = from.dwLocalAddr;
    const localAddrString = ip.inet_ntoa(addr);
    mem.copy(u8, result.localAddr[0..], mem.spanZ(localAddrString));

    addr.S_un.S_addr = from.dwRemoteAddr;
    const remoteAddrString = ip.inet_ntoa(addr);
    mem.copy(u8, result.remoteAddr[0..], mem.spanZ(remoteAddrString));

    result.localPort = ip.ntohs(@truncate(c_ushort, from.dwLocalPort));
    result.remotePort = ip.ntohs(@truncate(c_ushort, from.dwRemotePort));

    print("Local hello", .{});

    std.log.info("Local {s}:{}  -  Remote {s}:{}", .{
        mem.spanZ(result.localAddr[0..]),
        result.localPort,
        mem.spanZ(result.remoteAddr[0..]),
        result.remotePort,
    });

    return result;
}

fn print(comptime format: []const u8, args: anytype) void {
    const writer = std.io.getStdOut().writer();
    writer.print(format, args) catch unreachable;
}
