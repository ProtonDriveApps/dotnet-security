using Proton.Security.Cryptography.Abstractions;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp.Interop;

[StructLayout(LayoutKind.Sequential)]
[SuppressMessage("StyleCop.CSharp.MaintainabilityRules", "SA1401:Fields should be private", Justification = "Required for interop marshaling")]
internal sealed class InteropSignatureInput
{
    public IntPtr PrivateKey;
    public IntPtr Detachment;

    public static Disposable<InteropSignatureInput> Create(
        PrivatePgpKey privateKey,
        (PublicPgpKey? PublicKeyForEncryption, bool MustArmor)? detachedSignatureParameters,
        string? name = null)
    {
        var disposables = new List<IDisposable>(6);

        try
        {
            var signatureInput = new InteropSignatureInput { PrivateKey = privateKey.ToInteropDisposablePointer(disposables.Add) };

            if (detachedSignatureParameters is not null)
            {
                var (publicKeyForEncryption, mustArmor) = detachedSignatureParameters.Value;

                var detachmentSpecification = new InteropSignatureDetachmentInput(
                    publicKeyForEncryption.ToInteropDisposablePointer(disposables.Add),
                    mustArmor);

                signatureInput.Detachment = Marshaller.AllocateAndMarshal(detachmentSpecification, disposables.Add);
            }

            return new Disposable<InteropSignatureInput>(signatureInput, disposables);
        }
        catch
        {
            foreach (var disposable in disposables)
            {
                disposable.Dispose();
            }

            throw;
        }
    }
}
