using System.ComponentModel;

namespace Proton.Security.Cryptography;

public sealed class AsciiStream : Stream
{
    private readonly string _text;
    private int _position;

    public AsciiStream(string text)
    {
        _text = text ?? throw new ArgumentNullException(nameof(text));
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;

    public override long Length => _text.Length;

    public override long Position
    {
        get => _position;
        set
        {
            if (value > _text.Length || value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            _position = (int)value;
        }
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (offset > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(buffer));
        }

        if (offset + count > buffer.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        var bytesWritten = Encoding.ASCII.GetBytes(_text.AsSpan(_position, Math.Min(count, _text.Length - _position)), buffer.AsSpan(offset, count));

        _position += bytesWritten;

        return bytesWritten;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (offset > _text.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        var newPosition = origin switch
        {
            SeekOrigin.Begin => (int)offset,
            SeekOrigin.Current => unchecked(_position + (int)offset),
            SeekOrigin.End => unchecked(_text.Length + (int)offset),
            _ => throw new InvalidEnumArgumentException(nameof(origin), (int)origin, typeof(SeekOrigin))
        };

        if (newPosition < 0)
        {
            throw new IOException("Cannot seek before beginning of stream.");
        }

        _position = newPosition;

        return _position;
    }

    public override void SetLength(long value) => throw new InvalidOperationException();
    public override void Write(byte[] buffer, int offset, int count) => throw new InvalidOperationException();
}
