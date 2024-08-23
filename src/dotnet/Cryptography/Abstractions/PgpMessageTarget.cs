namespace Proton.Security.Cryptography.Abstractions;

public sealed class PgpMessageTarget : PgpDocumentEndpointBase
{
    public PgpMessageTarget(Stream stream, PgpArmoring armoring = PgpArmoring.None)
        : base(stream, armoring)
    {
        if (!stream.CanWrite)
        {
            throw new ArgumentException("Stream must be writable", nameof(stream));
        }
    }
}
