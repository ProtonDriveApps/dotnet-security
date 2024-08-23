using Proton.Security.InteropServices;

namespace Proton.Security.Interop;

internal static class CommonInterop
{
    private const string DllName = "ProtonSecurity";

    static CommonInterop()
    {
        GoInteropEnvironment.EnsureInitialized();
    }

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ReleaseArrayResultMemory(IntPtr pointer);
}
