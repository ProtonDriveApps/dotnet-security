namespace Proton.Security.Cryptography.Abstractions;

public sealed class PgpSignatureTarget : PgpDocumentEndpointBase
{
    public PgpSignatureTarget(Stream stream, PgpArmoring armoring = PgpArmoring.None)
        : base(stream, armoring)
    {
        if (!stream.CanWrite)
        {
            throw new ArgumentException("Stream must be writable", nameof(stream));
        }
    }
}
