using Microsoft.Win32.SafeHandles;

namespace Proton.Security.InteropServices;

internal sealed class DelegatingSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private readonly Action<IntPtr> _releaseAction;

    private DelegatingSafeHandle(Action<IntPtr> releaseAction)
        : base(true)
    {
        _releaseAction = releaseAction;
    }

    public static DelegatingSafeHandle FromPointer(IntPtr pointer, Action<IntPtr> releaseAction)
    {
        var result = new DelegatingSafeHandle(releaseAction);
        result.SetHandle(pointer);
        return result;
    }

    protected override bool ReleaseHandle()
    {
        _releaseAction.Invoke(handle);
        return true;
    }
}
