using Microsoft.Win32.SafeHandles;

namespace Proton.Security.Interop;

internal abstract class StructureHandle<T> : SafeHandleZeroOrMinusOneIsInvalid
    where T : struct
{
    protected StructureHandle()
        : base(ownsHandle: true)
    {
    }

    public T ToStructure()
    {
        return Marshal.PtrToStructure<T>(handle);
    }
}
