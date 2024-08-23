using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

internal sealed class EncryptionResultHandle : StructureHandle<EncryptionResult>
{
    protected override bool ReleaseHandle()
    {
        GopenPgpInterop.ReleaseEncryptionResultMemory(handle);
        return true;
    }
}
