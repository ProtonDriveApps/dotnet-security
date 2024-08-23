namespace Proton.Security.InteropServices;

internal static class IntPtrExtensions
{
    public static DelegatingSafeHandle AsSafeHandle(this IntPtr pointer, Action<IntPtr> releaseAction)
    {
        return DelegatingSafeHandle.FromPointer(pointer, releaseAction);
    }
}
