namespace Proton.Security.Interop;

internal sealed class InteropArrayResultHandle : StructureHandle<InteropArrayResult>
{
    protected override bool ReleaseHandle()
    {
        CommonInterop.ReleaseArrayResultMemory(handle);
        return true;
    }
}
