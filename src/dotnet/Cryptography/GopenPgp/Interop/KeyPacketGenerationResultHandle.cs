using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

internal sealed class KeyPacketGenerationResultHandle : StructureHandle<KeyPacketGenerationResult>
{
    protected override bool ReleaseHandle()
    {
        GopenPgpInterop.ReleaseKeyPacketGenerationResultMemory(handle);
        return true;
    }
}
