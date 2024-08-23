namespace Proton.Security.Cryptography.Abstractions;

public sealed class PgpSignatureSource : PgpDocumentEndpointBase
{
    public PgpSignatureSource(Stream stream, PgpArmoring armoring = PgpArmoring.None)
        : base(stream, armoring)
    {
        if (!stream.CanRead)
        {
            throw new ArgumentException("Stream must be readable", nameof(stream));
        }
    }
}
