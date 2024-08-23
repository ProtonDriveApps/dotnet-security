namespace Proton.Security.Cryptography.Abstractions;

public abstract class DataEndpointBase : IDisposable, IAsyncDisposable
{
    private bool _isDisposed;

    protected DataEndpointBase(Stream stream)
    {
        Stream = stream;
    }

    public Stream Stream { get; }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        return Stream.DisposeAsync();
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_isDisposed)
        {
            if (disposing)
            {
                Stream.Dispose();
            }

            _isDisposed = true;
        }
    }
}
