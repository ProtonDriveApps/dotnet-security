using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp;

internal sealed class SignatureStream : InteropArrayBasedStream<InteropArrayResult>
{
    private readonly PlainDataSource _plainDataSource;
    private readonly Func<Disposable<InteropSignatureInput>> _getSignatureInputFunction;
    private readonly Func<DateTimeOffset> _getTimestampFunction;

    public SignatureStream(
        PlainDataSource plainDataSource,
        Func<Disposable<InteropSignatureInput>> getSignatureInputFunction,
        Func<DateTimeOffset> getTimestampFunction)
    {
        _plainDataSource = plainDataSource;
        _getSignatureInputFunction = getSignatureInputFunction;
        _getTimestampFunction = getTimestampFunction;
    }

    protected override async Task<StructureHandle<InteropArrayResult>> GetInteropResultHandleAsync(CancellationToken cancellationToken)
    {
        var plainDataBytes = await _plainDataSource.GetBytesAsync(cancellationToken).ConfigureAwait(false);

        using var plainDataMemoryHandle = plainDataBytes.ToInteropArray();
        using var signatureInput = _getSignatureInputFunction.Invoke();

        return GopenPgpInterop.Sign(
            plainDataMemoryHandle.Value,
            _plainDataSource.Name,
            signatureInput.Value,
            _getTimestampFunction.Invoke().ToUnixTimeSeconds());
    }
}
