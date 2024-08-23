using Proton.Security.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

internal abstract class InteropArrayBasedStream<TInteropResult> : WrappingReadOnlyStream
    where TInteropResult : struct, IErrorProvider, IInteropArrayProvider
{
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    private bool _isDisposed;
    private bool _unmanagedMemoryHandleRefAdded = false;
    private StructureHandle<TInteropResult>? _unmanagedMemoryHandle;
    private TInteropResult? _interopResult;

    ~InteropArrayBasedStream()
    {
        Dispose(false);
    }

    protected bool HasInteropResult => _interopResult is not null;

    public override async ValueTask DisposeAsync()
    {
        await _semaphore.WaitAsync().ConfigureAwait(false);

        try
        {
            if (!_isDisposed && _unmanagedMemoryHandleRefAdded)
            {
                _unmanagedMemoryHandle?.DangerousRelease();
            }
        }
        finally
        {
            _isDisposed = true;
            _semaphore.Release();
        }

        await base.DisposeAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    protected Disposable<TInteropResult> GetInteropResult()
    {
        if (_interopResult is null || _unmanagedMemoryHandle is null)
        {
            throw new InvalidOperationException();
        }

        if (_unmanagedMemoryHandle.IsClosed)
        {
            throw new ObjectDisposedException("Interop result handle is closed");
        }

        var refAdded = false;
        _unmanagedMemoryHandle.DangerousAddRef(ref refAdded);
        return new Disposable<TInteropResult>(
            _interopResult.Value,
            () =>
            {
                if (refAdded)
                {
                    _unmanagedMemoryHandle.DangerousRelease();
                }
            });
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _semaphore.Wait();
        }

        try
        {
            if (!_isDisposed && _unmanagedMemoryHandleRefAdded)
            {
                // The handle object has a critical finalizer and should still be alive even if the code is being executed from the finalizer
                _unmanagedMemoryHandle?.DangerousRelease();
            }
        }
        finally
        {
            if (disposing)
            {
                _semaphore.Release();
            }

            _isDisposed = true;
        }

        base.Dispose(disposing);
    }

    protected abstract Task<StructureHandle<TInteropResult>> GetInteropResultHandleAsync(CancellationToken cancellationToken);

    protected virtual void OnGotInteropResult(in TInteropResult interopResult)
    {
    }

    protected override async Task<Stream> CreateUnderlyingStreamAsync(CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            _unmanagedMemoryHandle = await GetInteropResultHandleAsync(cancellationToken).ConfigureAwait(false);
            _unmanagedMemoryHandle.DangerousAddRef(ref _unmanagedMemoryHandleRefAdded);

            try
            {
                var interopResult = _unmanagedMemoryHandle.ToStructure();
                _interopResult = interopResult;

                ThrowIfError(interopResult);

                OnGotInteropResult(interopResult);

                unsafe
                {
                    return _interopResult.Value.GetInteropArray()->AsByteStream();
                }
            }
            catch
            {
                _unmanagedMemoryHandle.Dispose();
                _unmanagedMemoryHandle = null;
                throw;
            }
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private unsafe void ThrowIfError(IErrorProvider errorProvider)
    {
        var error = errorProvider.GetError();
        if (error is null)
        {
            return;
        }

        switch (error->Type)
        {
            default:
                throw new CryptographicException(error->GetMessage());
        }
    }
}
