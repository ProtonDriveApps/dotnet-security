namespace Proton.Security.Cryptography.Abstractions;

public abstract class PgpDocumentEndpointBase : DataEndpointBase
{
    protected PgpDocumentEndpointBase(Stream stream, PgpArmoring armoring = PgpArmoring.None)
        : base(stream)
    {
        Armoring = armoring;
    }

    public PgpArmoring Armoring { get; }
}
