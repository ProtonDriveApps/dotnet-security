using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.Abstractions;

public sealed class PlainDataSource : DataEndpointBase
{
    public PlainDataSource(SecureString secureString, string? name = default)
        : this(secureString.ToStream(), name)
    {
    }

    public PlainDataSource(Stream stream, string? name = default)
        : base(stream)
    {
        if (!stream.CanRead)
        {
            throw new ArgumentException("Stream must be readable", nameof(stream));
        }

        Name = name;
    }

    public string? Name { get; }
}
