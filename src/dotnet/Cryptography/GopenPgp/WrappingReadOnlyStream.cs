namespace Proton.Security.Cryptography.GopenPgp;

internal abstract class WrappingReadOnlyStream : Stream
{
    private Stream? _underlyingStream;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _underlyingStream?.Position ?? 0;
        set
        {
            if (value != (_underlyingStream?.Position ?? 0) && value != 0)
            {
                throw new InvalidOperationException("Cannot set an arbitrary position, only 0 and current position are supported.");
            }

            if (_underlyingStream is not null)
            {
                _underlyingStream.Position = 0;
            }
        }
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (offset != 0 || (origin != SeekOrigin.Begin && origin != SeekOrigin.Current))
        {
            throw new InvalidOperationException("Cannot seek to an arbitrary position, only beginning of stream and current position are supported.");
        }

        return _underlyingStream?.Seek(offset, origin) ?? 0;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer, offset, count).GetAwaiter().GetResult();
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var underlyingStream = await GetUnderlyingStreamAsync(cancellationToken).ConfigureAwait(false);
        return await underlyingStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
    {
        if (bufferSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(bufferSize));
        }

        if (!destination.CanWrite)
        {
            throw new NotSupportedException();
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromCanceled(cancellationToken);
        }

        return FinishCopyToAsync();

        async Task FinishCopyToAsync()
        {
            var underlyingStream = await GetUnderlyingStreamAsync(cancellationToken).ConfigureAwait(false);
            await underlyingStream.CopyToAsync(destination, bufferSize, cancellationToken).ConfigureAwait(false);
        }
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => throw new NotSupportedException();
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    protected virtual async Task<Stream> GetUnderlyingStreamAsync(CancellationToken cancellationToken)
    {
        return _underlyingStream ??= await CreateUnderlyingStreamAsync(cancellationToken).ConfigureAwait(false);
    }

    protected abstract Task<Stream> CreateUnderlyingStreamAsync(CancellationToken cancellationToken);
}
