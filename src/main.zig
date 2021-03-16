const std = @import("std");
const windows = std.os.windows;

const ip = @cImport({
    @cInclude("tcpmib.h");
});

pub extern "iphlpapi" fn GetTcpTable2(tcptable: ip.PMIB_TCPTABLE2, size: windows.ULONG, order: windows.BOOL) windows.ULONG;
pub extern "user32" fn MessageBoxA(hWnd: ?windows.HWND, lpText: windows.LPCSTR, lpCaption: windows.LPCSTR, uType: windows.UINT) c_int;

const c = @cImport({
    // See https://github.com/ziglang/zig/issues/515
    @cDefine("_NO_CRT_STDIO_INLINE", "1");
    @cInclude("stdio.h");
});

pub fn wWinMain(hInstance: windows.HINSTANCE, _: ?windows.HINSTANCE, lpCmdLine: windows.LPWSTR, nShowCmd: c_int) c_int {
    // this is here just to make the zig compiler happy
    return 0;
}

pub export fn WinMain(hInstance: windows.HINSTANCE, _: ?windows.HINSTANCE, lpCmdLine: windows.LPWSTR, nShowCmd: c_int) c_int {
    _ = MessageBoxA(null, "hello", "alive", 0);
    return 0;
}