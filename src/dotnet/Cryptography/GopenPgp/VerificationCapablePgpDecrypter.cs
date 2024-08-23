using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp;

public sealed class VerificationCapablePgpDecrypter : KeyBasedPgpDecrypter, IVerificationCapablePgpDecrypter
{
    private readonly IReadOnlyCollection<PublicPgpKey> _verificationKeys;

    public VerificationCapablePgpDecrypter(
        IReadOnlyCollection<PrivatePgpKey> privateKeys,
        IReadOnlyCollection<PublicPgpKey> verificationKeys)
        : base(privateKeys)
    {
        _verificationKeys = verificationKeys;
    }

    public DecryptingAndVerifyingStreamProvisionResult GetDecryptingAndVerifyingStream(PgpMessageSource messageSource)
    {
        return GetDecryptingAndVerifyingStream(messageSource, default((PgpDocumentEndpointBase, bool)?));
    }

    public DecryptingAndVerifyingStreamWithSessionKeyProvisionResult GetDecryptingAndVerifyingStreamWithSessionKey(PgpMessageSource messageSource)
    {
        return GetDecryptingAndVerifyingStreamWithSessionKey(messageSource, default((PgpDocumentEndpointBase, bool)?));
    }

    public DecryptingAndVerifyingStreamProvisionResult GetDecryptingAndVerifyingStream(
        PgpMessageSource messageSource,
        PgpSignatureSource detachedSignatureSource)
    {
        return GetDecryptingAndVerifyingStream(messageSource, (detachedSignatureSource, false));
    }

    public DecryptingAndVerifyingStreamWithSessionKeyProvisionResult GetDecryptingAndVerifyingStreamWithSessionKey(
        PgpMessageSource messageSource,
        PgpSignatureSource detachedSignatureSource)
    {
        return GetDecryptingAndVerifyingStreamWithSessionKey(messageSource, (detachedSignatureSource, false));
    }

    public DecryptingAndVerifyingStreamProvisionResult GetDecryptingAndVerifyingStream(
        PgpMessageSource messageSource,
        PgpMessageSource detachedSignatureMessageSource)
    {
        return GetDecryptingAndVerifyingStream(messageSource, (detachedSignatureMessageSource, true));
    }

    public DecryptingAndVerifyingStreamWithSessionKeyProvisionResult GetDecryptingAndVerifyingStreamWithSessionKey(
        PgpMessageSource messageSource,
        PgpMessageSource detachedSignatureMessageSource)
    {
        return GetDecryptingAndVerifyingStreamWithSessionKey(messageSource, (detachedSignatureMessageSource, true));
    }

    public async Task<VerificationVerdict> VerifyAsync(ReadOnlyMemory<byte> plainData, PgpSignatureSource signatureSource, CancellationToken cancellationToken)
    {
        using var interopPlainData = plainData.ToInteropArray();

        var signatureBytes = await signatureSource.GetBytesAsync(cancellationToken).ConfigureAwait(false);

        var disposables = new List<IDisposable>(_verificationKeys.Count + 1);

        try
        {
            var interopVerificationInput = InteropVerificationInput.Create(_verificationKeys, (signatureBytes, signatureSource.Armoring, false), disposables.Add);

            var interopResultHandle = GopenPgpInterop.Verify(interopPlainData.Value, interopVerificationInput);

            unsafe
            {
                using (interopResultHandle)
                {
                    var interopResult = interopResultHandle.ToStructure((_, message) => new CryptographicException(message));
                    return interopResult.VerificationOutput->Code;
                }
            }
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

    private DecryptingAndVerifyingStreamProvisionResult GetDecryptingAndVerifyingStream(
        PgpMessageSource messageSource,
        (PgpDocumentEndpointBase DataEndpoint, bool IsEncrypted)? detachedSignatureSource)
    {
        var verificationTaskCompletionSource = new TaskCompletionSource<VerificationVerdict>();

        var stream = new DecryptingStream(ct => CreateDecryptionInputAsync(messageSource, ct), ct => CreateVerificationInputAsync(detachedSignatureSource, ct));

        stream.VerificationDone += (_, args) => verificationTaskCompletionSource.SetResult(args.Verdict);

        return new(stream, verificationTaskCompletionSource.Task);
    }

    private DecryptingAndVerifyingStreamWithSessionKeyProvisionResult GetDecryptingAndVerifyingStreamWithSessionKey(
        PgpMessageSource messageSource,
        (PgpDocumentEndpointBase DataEndpoint, bool IsEncrypted)? detachedSignatureSource)
    {
        var verificationTaskCompletionSource = new TaskCompletionSource<VerificationVerdict>();
        var sessionKeyTaskCompletionSource = new TaskCompletionSource<PgpSessionKey>();

        var stream = new DecryptingStream(
            ct => CreateDecryptionInputAsync(messageSource, ct),
            ct => CreateVerificationInputAsync(detachedSignatureSource, ct),
            sessionKeyTaskCompletionSource.SetResult);

        stream.VerificationDone += (_, args) => verificationTaskCompletionSource.SetResult(args.Verdict);

        return new(stream, verificationTaskCompletionSource.Task, sessionKeyTaskCompletionSource.Task);
    }

    private async Task<Disposable<InteropVerificationInput?>> CreateVerificationInputAsync(
        (PgpDocumentEndpointBase DataEndpoint, bool IsEncrypted)? detachedSignatureSource,
        CancellationToken cancellationToken)
    {
        (ReadOnlyMemory<byte> Bytes, PgpArmoring Format, bool IsEncrypted)? detachedSignature = null;
        if (detachedSignatureSource != null)
        {
            var (dataEndpoint, isEncrypted) = detachedSignatureSource.Value;

            var detachedSignatureBytes = await dataEndpoint.GetBytesAsync(cancellationToken).ConfigureAwait(false);

            detachedSignature = (detachedSignatureBytes, dataEndpoint.Armoring, isEncrypted);
        }

        var disposables = new List<IDisposable>(_verificationKeys.Count + 1);
        try
        {
            var interopVerificationInput = InteropVerificationInput.Create(_verificationKeys, detachedSignature, disposables.Add);

            return new Disposable<InteropVerificationInput?>(interopVerificationInput, disposables);
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
