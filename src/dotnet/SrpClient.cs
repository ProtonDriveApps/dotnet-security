using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security;

public sealed class SrpClient : ISrpClient
{
    static SrpClient()
    {
        GoInteropEnvironment.EnsureInitialized();
    }

    public SrpClientResponse CalculateResponse(
        SrpServerGeneratedChallenge challenge,
        ReadOnlySpan<byte> salt,
        string signedModulus,
        string username,
        SecureString password)
    {
        SrpProofGenerationResultHandle? interopResultHandle;
        using (var passwordArray = password.ToInteropArray())
        {
            (int version, ReadOnlyMemory<byte> ephemeral, int bitLength) = challenge;

            interopResultHandle = SrpInterop.GenerateProofs(
                version,
                username,
                passwordArray.Value,
                Convert.ToBase64String(salt),
                signedModulus,
                Convert.ToBase64String(ephemeral.Span),
                bitLength);
        }

        using (interopResultHandle)
        {
            var interopResult = interopResultHandle.ToStructure();

            if (!string.IsNullOrEmpty(interopResult.Error))
            {
                throw new SrpException(interopResult.Error);
            }

            unsafe
            {
                var clientGeneratedChallenge = new SrpClientGeneratedChallenge(
                    interopResult.ClientEphemeral->ToArray(),
                    interopResult.ExpectedServerProof->ToArray());

                return new SrpClientResponse(interopResult.ClientProof->ToArray(), clientGeneratedChallenge);
            }
        }
    }
}
