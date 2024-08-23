namespace Proton.Security.Cryptography.Abstractions;

public sealed class PublicPgpKey : PgpKey
{
    public PublicPgpKey(ReadOnlyMemory<byte> data, bool dataIsArmored)
        : base(data, dataIsArmored)
    {
    }

    public static PublicPgpKey FromArmored(ReadOnlyMemory<byte> armoredKeyBlock)
    {
        return new(armoredKeyBlock, true);
    }

    public static PublicPgpKey FromArmored(string armoredKeyBlock)
    {
        return FromArmored(Encoding.ASCII.GetBytes(armoredKeyBlock));
    }
}
