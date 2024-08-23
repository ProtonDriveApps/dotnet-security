using Proton.Security.Cryptography.Abstractions;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
[SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1401:Fields should be private", Justification = "Required for interop marshaling")]
internal sealed class InteropVerificationInput
{
    public IntPtr PublicKeys;
    public int PublicKeysLength;
    public IntPtr DetachedSignature;

    public static InteropVerificationInput Create(
        IReadOnlyCollection<PublicPgpKey> verificationKeys,
        (ReadOnlyMemory<byte> Bytes, PgpArmoring Format, bool IsEncrypted)? detachedSignature,
        Action<IDisposable> registerDisposableAction)
    {
        var verificationInput = new InteropVerificationInput
        {
            PublicKeys = verificationKeys.ToInteropDisposablePointer(registerDisposableAction),
            PublicKeysLength = verificationKeys.Count
        };

        if (detachedSignature != null)
        {
            var (signatureBytes, signatureFormat, isEncrypted) = detachedSignature.Value;

            var interopSignature = new InteropSignature
            {
                Data = signatureBytes.ToInteropArray(registerDisposableAction),
                IsEncrypted = isEncrypted,
                IsArmored = signatureFormat == PgpArmoring.Ascii
            };

            verificationInput.DetachedSignature = Marshaller.AllocateAndMarshal(interopSignature, registerDisposableAction);
        }

        return verificationInput;
    }
}
