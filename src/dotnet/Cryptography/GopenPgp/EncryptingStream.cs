using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

internal sealed class EncryptingStream : InteropArrayBasedStream<EncryptionResult>
{
    private readonly PlainDataSource _plainDataSource;
    private readonly Func<DateTimeOffset> _getTimestampFunction;
    private readonly Func<ReadOnlyMemory<byte>, string?, Disposable<InteropEncryptionInput>> _getEncryptionInputFunction;
    private readonly Func<Disposable<InteropSignatureInput>>? _getSignatureInputFunction;
    private readonly Action<PgpSessionKey>? _sessionKeyDecryptedHandler;

    public EncryptingStream(
        Func<ReadOnlyMemory<byte>, string?, Disposable<InteropEncryptionInput>> getEncryptionInputFunction,
        PlainDataSource plainDataSource,
        Func<DateTimeOffset> getTimestampFunction)
    {
        _getEncryptionInputFunction = getEncryptionInputFunction;
        _plainDataSource = plainDataSource;
        _getTimestampFunction = getTimestampFunction;
    }

    public EncryptingStream(
        Func<ReadOnlyMemory<byte>, string?, Disposable<InteropEncryptionInput>> getEncryptionInputFunction,
        PlainDataSource plainDataSource,
        Action<PgpSessionKey> sessionKeyDecryptedHandler,
        Func<DateTimeOffset> getTimestampFunction)
        : this(getEncryptionInputFunction, plainDataSource, getTimestampFunction)
    {
        _sessionKeyDecryptedHandler = sessionKeyDecryptedHandler;
    }

    public EncryptingStream(
        Func<ReadOnlyMemory<byte>, string?, Disposable<InteropEncryptionInput>> getEncryptionInputFunction,
        Func<Disposable<InteropSignatureInput>> getSignatureInputFunction,
        PlainDataSource plainDataSource,
        Func<DateTimeOffset> getTimestampFunction)
        : this(getEncryptionInputFunction, plainDataSource, getTimestampFunction)
    {
        _getSignatureInputFunction = getSignatureInputFunction;
    }

    private EncryptingStream(
        Func<ReadOnlyMemory<byte>, string?, Disposable<InteropEncryptionInput>> getEncryptionInputFunction,
        Func<Disposable<InteropSignatureInput>> getSignatureInputFunction,
        PlainDataSource plainDataSource,
        Action<PgpSessionKey> sessionKeyDecryptedHandler,
        Func<DateTimeOffset> getTimestampFunction)
        : this(getEncryptionInputFunction, getSignatureInputFunction, plainDataSource, getTimestampFunction)
    {
        _sessionKeyDecryptedHandler = sessionKeyDecryptedHandler;
    }

    public static (EncryptingStream EncryptingStream, Stream SignatureStream) CreateWithSignatureStream(
        Func<ReadOnlyMemory<byte>, string?, Disposable<InteropEncryptionInput>> getEncryptionInputFunction,
        Func<Disposable<InteropSignatureInput>> getSignatureInputFunction,
        PlainDataSource plainDataSource,
        Func<DateTimeOffset> getTimestampFunction)
    {
        var encryptingStream = new EncryptingStream(getEncryptionInputFunction, getSignatureInputFunction, plainDataSource, getTimestampFunction);
        var signatureStream = new DependentSignatureStream(encryptingStream);
        return (encryptingStream, signatureStream);
    }

    public static (EncryptingStream EncryptingStream, Stream SignatureStream) CreateWithSignatureStream(
        Func<ReadOnlyMemory<byte>, string?, Disposable<InteropEncryptionInput>> getEncryptionInputFunction,
        Func<Disposable<InteropSignatureInput>> getSignatureInputFunction,
        PlainDataSource plainDataSource,
        Action<PgpSessionKey> sessionKeyDecryptedHandler,
        Func<DateTimeOffset> getTimestampFunction)
    {
        var encryptingStream = new EncryptingStream(
            getEncryptionInputFunction,
            getSignatureInputFunction,
            plainDataSource,
            sessionKeyDecryptedHandler,
            getTimestampFunction);
        var signatureStream = new DependentSignatureStream(encryptingStream);
        return (encryptingStream, signatureStream);
    }

    protected override async Task<StructureHandle<EncryptionResult>> GetInteropResultHandleAsync(CancellationToken cancellationToken)
    {
        var plainDataBytes = await _plainDataSource.GetBytesAsync(cancellationToken).ConfigureAwait(false);

        using var encryptionInput = _getEncryptionInputFunction.Invoke(plainDataBytes, _plainDataSource.Name);
        using var signatureInput = _getSignatureInputFunction?.Invoke();

        return GopenPgpInterop.Encrypt(
            encryptionInput.Value,
            signatureInput?.Value,
            _getTimestampFunction.Invoke().ToUnixTimeSeconds(),
            includeSessionKeyInResult: true);
    }

    protected override unsafe void OnGotInteropResult(in EncryptionResult interopResult)
    {
        if (_sessionKeyDecryptedHandler is null || interopResult.SessionKey->AlgorithmId is null)
        {
            return;
        }

        var sessionKey = new PgpSessionKey(interopResult.SessionKey->Data.ToArray(), interopResult.SessionKey->GetAlgorithmId());

        _sessionKeyDecryptedHandler.Invoke(sessionKey);
    }

    // TODO: add a finalizer to avoid leaks if the object wasn't explicitly disposed
    private sealed unsafe class DependentSignatureStream : WrappingReadOnlyStream
    {
        private readonly EncryptingStream _owner;

        private IDisposable? _interopResultDisposable;
        private InteropArray? _signatureInteropArray;

        public DependentSignatureStream(EncryptingStream owner)
        {
            _owner = owner;
        }

        public override bool CanRead => _owner.HasInteropResult && base.CanRead;

        protected override Task<Stream> CreateUnderlyingStreamAsync(CancellationToken cancellationToken)
        {
            if (_signatureInteropArray is null)
            {
                if (!_owner.HasInteropResult)
                {
                    throw new InvalidOperationException("Cannot stream signature because the source stream has not yet been read.");
                }

                var interopResult = _owner.GetInteropResult();
                _interopResultDisposable = interopResult;

                if (interopResult.Value.DetachedSignature == null)
                {
                    throw new InvalidOperationException("No detached signature has been created.");
                }

                _signatureInteropArray = interopResult.Value.DetachedSignature->Data;
            }

            return Task.FromResult(_signatureInteropArray.Value.AsByteStream());
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _interopResultDisposable is not null)
            {
                _interopResultDisposable.Dispose();
                _interopResultDisposable = null;
            }

            base.Dispose(disposing);
        }
    }
}
