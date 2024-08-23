using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

// TODO: make this take the PgpMessageSource and PgpSignatureSource objects so that it can dispose them
internal sealed class DecryptingStream : InteropArrayBasedStream<DecryptionResult>
{
    private readonly Func<CancellationToken, Task<Disposable<InteropDecryptionInput>>> _getDecryptionInputAsyncFunction;
    private readonly Func<CancellationToken, Task<Disposable<InteropVerificationInput?>>> _getVerificationInputAsyncFunction;
    private readonly Action<PgpSessionKey>? _sessionKeyDecryptedHandler;

    public DecryptingStream(
        Func<CancellationToken, Task<Disposable<InteropDecryptionInput>>> getDecryptionInputAsyncFunction,
        Func<CancellationToken, Task<Disposable<InteropVerificationInput?>>> getVerificationInputAsyncFunction,
        Action<PgpSessionKey> sessionKeyDecryptedHandler)
        : this(getDecryptionInputAsyncFunction, getVerificationInputAsyncFunction)
    {
        _sessionKeyDecryptedHandler = sessionKeyDecryptedHandler;
    }

    public DecryptingStream(
        Func<CancellationToken, Task<Disposable<InteropDecryptionInput>>> getDecryptionInputAsyncFunction,
        Func<CancellationToken, Task<Disposable<InteropVerificationInput?>>> getVerificationInputAsyncFunction)
    {
        _getDecryptionInputAsyncFunction = getDecryptionInputAsyncFunction;
        _getVerificationInputAsyncFunction = getVerificationInputAsyncFunction;
    }

    public DecryptingStream(Func<CancellationToken, Task<Disposable<InteropDecryptionInput>>> getDecryptionInputAsyncFunction)
        : this(getDecryptionInputAsyncFunction, _ => Task.FromResult(new Disposable<InteropVerificationInput?>(default, Enumerable.Empty<Action>())))
    {
    }

    public DecryptingStream(
        Func<CancellationToken, Task<Disposable<InteropDecryptionInput>>> getDecryptionInputAsyncFunction,
        Action<PgpSessionKey> sessionKeyDecryptedHandler)
        : this(
            getDecryptionInputAsyncFunction,
            _ => Task.FromResult(new Disposable<InteropVerificationInput?>(default, Enumerable.Empty<Action>())),
            sessionKeyDecryptedHandler)
    {
    }

    public event EventHandler<VerificationDoneEventArgs>? VerificationDone;

    protected override async Task<StructureHandle<DecryptionResult>> GetInteropResultHandleAsync(CancellationToken cancellationToken)
    {
        var (verificationInput, decryptionInput) = await ParallelTask.WhenBothDisposable(
            () => _getVerificationInputAsyncFunction.Invoke(cancellationToken),
            () => _getDecryptionInputAsyncFunction.Invoke(cancellationToken)).ConfigureAwait(false);

        using (decryptionInput)
        using (verificationInput)
        {
            return GopenPgpInterop.Decrypt(decryptionInput.Value, verificationInput.Value, _sessionKeyDecryptedHandler is not null);
        }
    }

    protected override unsafe void OnGotInteropResult(in DecryptionResult interopResult)
    {
        var interopSessionKey = interopResult.DecryptionOutput->SessionKey;

        if (_sessionKeyDecryptedHandler is not null && interopSessionKey->AlgorithmId is not null)
        {
            var sessionKey = new PgpSessionKey(interopSessionKey->Data.ToArray(), interopSessionKey->GetAlgorithmId());

            _sessionKeyDecryptedHandler.Invoke(sessionKey);
        }

        if (interopResult.VerificationOutput is not null)
        {
            VerificationDone?.Invoke(this, new VerificationDoneEventArgs(interopResult.VerificationOutput->Code));
        }
    }
}
