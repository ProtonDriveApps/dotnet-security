namespace Proton.Security;

internal class WrappingStream : Stream
{
    private readonly Stream _underlyingStream;
    private readonly bool _wrapsClose;

    public WrappingStream(Stream underlyingStream, bool wrapsClose = false)
    {
        _underlyingStream = underlyingStream;
        _wrapsClose = wrapsClose;
    }

    public override bool CanRead => _underlyingStream.CanRead;
    public override bool CanSeek => _underlyingStream.CanSeek;
    public override bool CanWrite => _underlyingStream.CanWrite;
    public override bool CanTimeout => _underlyingStream.CanTimeout;
    public override long Length => _underlyingStream.Length;

    public override long Position
    {
        get => _underlyingStream.Position;
        set => _underlyingStream.Position = value;
    }

    public override int ReadTimeout
    {
        get => _underlyingStream.ReadTimeout;
        set => _underlyingStream.ReadTimeout = value;
    }

    public override int WriteTimeout
    {
        get => _underlyingStream.WriteTimeout;
        set => _underlyingStream.WriteTimeout = value;
    }

    public override void Flush() => _underlyingStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _underlyingStream.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count) => _underlyingStream.Read(buffer, offset, count);

    public override int Read(Span<byte> buffer) => _underlyingStream.Read(buffer);

    public override int ReadByte() => _underlyingStream.ReadByte();

    public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state)
        => _underlyingStream.BeginRead(buffer, offset, count, callback, state);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _underlyingStream.ReadAsync(buffer, offset, count, cancellationToken);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _underlyingStream.ReadAsync(buffer, cancellationToken);

    public override int EndRead(IAsyncResult asyncResult) => _underlyingStream.EndRead(asyncResult);

    public override long Seek(long offset, SeekOrigin origin) => _underlyingStream.Seek(offset, origin);

    public override void SetLength(long value) => _underlyingStream.SetLength(value);

    public override void Write(byte[] buffer, int offset, int count) => _underlyingStream.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => _underlyingStream.Write(buffer);

    public override void WriteByte(byte value) => _underlyingStream.WriteByte(value);

    public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback? callback, object? state)
        => _underlyingStream.BeginWrite(buffer, offset, count, callback, state);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _underlyingStream.WriteAsync(buffer, offset, count, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _underlyingStream.WriteAsync(buffer, cancellationToken);

    public override void EndWrite(IAsyncResult asyncResult) => _underlyingStream.EndWrite(asyncResult);

    public override void CopyTo(Stream destination, int bufferSize) => _underlyingStream.CopyTo(destination, bufferSize);

    public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        => _underlyingStream.CopyToAsync(destination, bufferSize, cancellationToken);

    public override bool Equals(object? obj) => _underlyingStream.Equals(obj);

    public override int GetHashCode() => _underlyingStream.GetHashCode();

    public override string? ToString() => _underlyingStream.ToString();

    public override void Close()
    {
        if (_wrapsClose)
        {
            _underlyingStream.Close();
        }
        else
        {
            base.Close();
        }
    }

    [SuppressMessage("Usage", "CA2215:Dispose methods should call base class dispose", Justification = "Base does nothing, this is a pure wrapper")]
    public override ValueTask DisposeAsync() => _underlyingStream.DisposeAsync();

    [SuppressMessage("Usage", "CA2215:Dispose methods should call base class dispose", Justification = "Base does nothing, this is a pure wrapper")]
    protected override void Dispose(bool disposing) => _underlyingStream.Dispose();
}
