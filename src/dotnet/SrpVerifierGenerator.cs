using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security;

public sealed class SrpVerifierGenerator : ISrpVerifierGenerator
{
    private const int SrpBitLength = 2048;

    public ReadOnlyMemory<byte> Generate(SecureString password, ReadOnlyMemory<byte> salt, string signedModulus)
    {
        InteropArrayResultHandle? interopResultHandle;
        using (var passwordArray = password.ToInteropArray())
        using (var saltArray = salt.ToInteropArray())
        {
            interopResultHandle = SrpInterop.GenerateVerifier(passwordArray.Value, saltArray.Value, signedModulus, SrpBitLength);
        }

        using (interopResultHandle)
        {
            return interopResultHandle.GetBytes((_, message) => new SrpException(message));
        }
    }
}
