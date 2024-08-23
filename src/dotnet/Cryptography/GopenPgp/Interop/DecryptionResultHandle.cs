using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

internal sealed class DecryptionResultHandle : StructureHandle<DecryptionResult>
{
    protected override bool ReleaseHandle()
    {
        GopenPgpInterop.ReleaseDecryptionResultMemory(handle);
        return true;
    }
}
