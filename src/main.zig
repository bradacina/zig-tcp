const std = @import("std");
const windows = std.os.windows;
const alloc = std.mem.Allocator;
const mem = std.mem;

const ip = @cImport({
    // @cInclude("_mingw.h");
    @cInclude("initguid.h");
    @cInclude("winsock2.h");
    @cInclude("ws2tcpip.h");
    @cInclude("iphlpapi.h");
    @cInclude("comutil.h");
    // @cInclude("atlcomcli.h");
    @cInclude("netfw.h");
});

const RPC_E_CHANGED_MODE = 0x80010106;

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

// pub fn main() !void {
//     var len: u32 = 2000;
//     const allocator: *mem.Allocator = std.heap.page_allocator;
//     const buffer = try allocator.allocAdvanced(u8, @alignOf(ip.MIB_TCPTABLE2), len, alloc.Exact.exact);
//     const tablePointer = @ptrCast(ip.PMIB_TCPTABLE2, buffer);

//     const res = ip.GetTcpTable2(tablePointer, &len, windows.TRUE);
//     std.log.info("Result {}, Length {}", .{ res, len });

//     var numEntries = tablePointer.*.dwNumEntries;
//     var table = @ptrCast([*]ip.MIB_TCPROW2, &tablePointer.*.table);

//     var i: usize = 0;
//     var results: []row = try allocator.alloc(row, numEntries);
//     while (i < numEntries) : (i += 1) {
//         results[i] = toRow(table[i]);
//     }
// }

pub fn main() !void {
    try getFirewallRules();
}

fn getFirewallRules() !void {
    var hrComInit: ip.HRESULT = ip.S_OK;
    var hr: ip.HRESULT = ip.S_OK;

    var cFetched: ip.ULONG = 0;
    var variant: *ip.VARIANTARG = undefined;
    ip.VariantInit(variant);

    var pEnumerator: ?*ip.IUnknown = null;
    var pVariant: ?*ip.IEnumVARIANT = null;

    var pNetFwPolicy2: ?*ip.INetFwPolicy2 = null;
    var pFwRules: ?*ip.INetFwRules = null;
    var pFwRule: ?*ip.INetFwRule = null;

    var fwRuleCount: i32 = 0;

    defer {}

    // Initialize COM.
    hrComInit = ip.CoInitializeEx(null, ip.COINIT_APARTMENTTHREADED);

    if (hrComInit != RPC_E_CHANGED_MODE) {
        if (hrComInit < 0) {
            print("CoInitializeEx failed: {}\n", .{hrComInit});
            return;
        }
    }

    hr = WFCOMInitialize(&pNetFwPolicy2);
    if (hr < 0) {
        return;
    }

    // Retrieve INetFwRules
    hr = pNetFwPolicy2.?.*.lpVtbl.*.get_Rules.?(pNetFwPolicy2.?, &pFwRules);
    if (hr < 0) {
        print("get_Rules failed: {}\n", .{hr});
        return;
    }

    // Get count of rules
    hr = pFwRules.?.*.lpVtbl.*.get_Count.?(pFwRules.?, &fwRuleCount);
    if (hr < 0) {
        print("get_Count failed: {}\n", .{hr});
        return;
    }

    print("The number of rules in the Windows Firewall are {}\n", .{fwRuleCount});

    // Iterate through all of the rules in pFwRules
    _ = pFwRules.?.*.lpVtbl.*.get__NewEnum.?(pFwRules.?, &pEnumerator);

    if (pEnumerator) |pEnumerator_| {
        hr = pEnumerator_.lpVtbl.*.QueryInterface.?(
            pEnumerator, 
            &ip.IID_IEnumVARIANT, 
            @ptrCast([*c]?*c_void,&pVariant));
    }

    while(hr > 0 and hr != ip.S_FALSE)
    {
        _= ip.VariantClear(variant);

        hr = pVariant.?.*.lpVtbl.*.Next.?(pVariant.?,1, variant, &cFetched);

        if (ip.S_FALSE != hr)
        {
            if (hr>0)
            {
                hr = ip.VariantChangeType( VT_DISPATCH);
            }
        //     if (hr>=0)
        //     {
        //         hr = (V_DISPATCH(&amp;var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&amp;pFwRule));
        //     }

        //     if (hr>=0)
        //     {
        //         // Output the properties of this rule
        //         DumpFWRulesInCollection(pFwRule);
        //     }
        }
    }
}

fn WFCOMInitialize(ppNetFwPolicy2: *?*ip.INetFwPolicy2) ip.HRESULT {
    var hr: ip.HRESULT = ip.S_OK;

    hr = ip.CoCreateInstance(&ip.CLSID_NetFwPolicy2, null, ip.CLSCTX_INPROC_SERVER, &ip.IID_INetFwPolicy2, @ptrCast([*c]?*c_void, ppNetFwPolicy2));

    if (hr < 0) {
        print("CoCreateInstance for INetFwPolicy2 failed: {}\n", .{hr});
        return hr;
    }

    return hr;
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

    print("Local {s}:{}  -  Remote {s}:{} - {s} - PID:{}\n", .{
        mem.spanZ(result.localAddr[0..]),
        result.localPort,
        mem.spanZ(result.remoteAddr[0..]),
        result.remotePort,
        stateToString(from.dwState),
        from.dwOwningPid,
    });

    return result;
}

fn getPidDetails(pid: int) []const u8 {}

fn stateToString(dwState: ip.DWORD) []const u8 {
    return switch (dwState) {
        ip.MIB_TCP_STATE_CLOSED => "Closed",
        ip.MIB_TCP_STATE_LISTEN => "Listening",
        ip.MIB_TCP_STATE_SYN_SENT => "SYN Sent",
        ip.MIB_TCP_STATE_SYN_RCVD => "SYN Received",
        ip.MIB_TCP_STATE_ESTAB => "Established",
        ip.MIB_TCP_STATE_FIN_WAIT1, ip.MIB_TCP_STATE_FIN_WAIT2 => "FIN Wait",
        ip.MIB_TCP_STATE_CLOSE_WAIT => "Close Wait",
        ip.MIB_TCP_STATE_CLOSING => "Closing",
        ip.MIB_TCP_STATE_LAST_ACK => "Last ACK",
        ip.MIB_TCP_STATE_TIME_WAIT => "Time Wait",
        ip.MIB_TCP_STATE_DELETE_TCB => "Delete TCB",
        else => "Unknown",
    };
}

fn print(comptime format: []const u8, args: anytype) void {
    const writer = std.io.getStdOut().writer();
    writer.print(format, args) catch unreachable;
}
