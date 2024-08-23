namespace Proton.Security.Interop;

internal sealed class SrpProofGenerationResultHandle : StructureHandle<InteropProofGenerationResult>
{
    protected override bool ReleaseHandle()
    {
        SrpInterop.ReleaseProofGenerationResultMemory(handle);
        return true;
    }
}
