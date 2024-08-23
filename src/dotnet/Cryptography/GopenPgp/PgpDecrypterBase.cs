using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp;

public abstract class PgpDecrypterBase : IPgpDecrypter
{
    protected abstract int PrivateKeyCount { get; }

    public PgpSessionKey DecryptSessionKey(ReadOnlyMemory<byte> keyPacket)
    {
        var disposables = new List<IDisposable>(Math.Min(1, PrivateKeyCount * 2) + 1);

        SessionKeyResultHandle interopResultHandle;

        try
        {
            var privateKeyArrayPointer = GetPrivateKeysPointer(disposables.Add);
            var interopKeyPacket = keyPacket.ToInteropArray(disposables.Add);
            var passwordPointer = GetPasswordPointer(disposables.Add);

            interopResultHandle = GopenPgpInterop.DecryptSessionKey(privateKeyArrayPointer, PrivateKeyCount, passwordPointer, interopKeyPacket);
        }
        finally
        {
            foreach (var disposable in disposables)
            {
                disposable.Dispose();
            }
        }

        var interopResult = interopResultHandle.ToStructure();

        unsafe
        {
            if (interopResult.Error is not null)
            {
                throw new CryptographicException(Marshal.PtrToStringUTF8(new IntPtr(interopResult.Error)));
            }
        }

        unsafe
        {
            var result = new PgpSessionKey(interopResult.SessionKey->Data.ToArray(), interopResult.SessionKey->GetAlgorithmId());
            return result;
        }
    }

    public Stream GetDecryptingStream(PgpMessageSource messageSource)
    {
        return new DecryptingStream(ct => CreateDecryptionInputAsync(messageSource, ct));
    }

    public (Stream Stream, Task<PgpSessionKey> SessionKey) GetDecryptingStreamWithSessionKey(PgpMessageSource messageSource)
    {
        var sessionKeyTaskCompletionSource = new TaskCompletionSource<PgpSessionKey>();
        var stream = new DecryptingStream(ct => CreateDecryptionInputAsync(messageSource, ct), sessionKeyTaskCompletionSource.SetResult);
        return (stream, sessionKeyTaskCompletionSource.Task);
    }

    protected abstract IntPtr GetPrivateKeysPointer(Action<IDisposable> registerDisposableAction);
    protected abstract IntPtr GetPasswordPointer(Action<IDisposable> registerDisposableAction);

    private protected async Task<Disposable<InteropDecryptionInput>> CreateDecryptionInputAsync(
        PgpMessageSource messageSource,
        CancellationToken cancellationToken)
    {
        var disposables = new List<IDisposable>(Math.Min(1, PrivateKeyCount * 2) + 1);

        var messageBytes = await messageSource.GetBytesAsync(cancellationToken).ConfigureAwait(false);

        var decryptionInput = new InteropDecryptionInput
        {
            PrivateKeys = GetPrivateKeysPointer(disposables.Add),
            PrivateKeysLength = PrivateKeyCount,
            Password = GetPasswordPointer(disposables.Add),
            Message = messageBytes.ToInteropArray(disposables.Add),
            MessageIsArmored = messageSource.Armoring == PgpArmoring.Ascii
        };

        return new Disposable<InteropDecryptionInput>(decryptionInput, disposables);
    }
}
