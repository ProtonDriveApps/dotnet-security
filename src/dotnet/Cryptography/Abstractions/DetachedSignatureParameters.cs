namespace Proton.Security.Cryptography.Abstractions;

public readonly struct DetachedSignatureParameters
{
    private DetachedSignatureParameters(PgpSignatureSecurity security, PgpArmoring armoring = PgpArmoring.None)
    {
        Security = security;
        Armoring = armoring;
    }

    public static DetachedSignatureParameters Plain => new(PgpSignatureSecurity.Plain);
    public static DetachedSignatureParameters Encrypted => new(PgpSignatureSecurity.Encrypted);

    public static DetachedSignatureParameters ArmoredPlain => new(PgpSignatureSecurity.Plain, PgpArmoring.Ascii);
    public static DetachedSignatureParameters ArmoredEncrypted => new(PgpSignatureSecurity.Encrypted, PgpArmoring.Ascii);

    public PgpSignatureSecurity Security { get; }
    public PgpArmoring Armoring { get; }
}
