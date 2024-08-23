namespace Proton.Security.Cryptography.Abstractions;

public sealed class PgpMessageSource : PgpDocumentEndpointBase
{
    public PgpMessageSource(Stream stream, PgpArmoring armoring = PgpArmoring.None)
        : base(stream, armoring)
    {
        if (!stream.CanRead)
        {
            throw new ArgumentException("Stream must be readable", nameof(stream));
        }
    }
}
