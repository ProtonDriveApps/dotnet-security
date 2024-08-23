namespace Proton.Security.Cryptography.Abstractions;

public sealed class PrivatePgpKey : PgpKey
{
    private PublicPgpKey? _publicKey;

    private PrivatePgpKey(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> passphrase, bool dataIsArmored)
        : base(data, dataIsArmored)
    {
        Passphrase = passphrase;
    }

    // We're cheating here because we don't (yet) have the logic to extract the public key from the private key packet.
    // The consumer will need to detect that it's actually a (locked) private key packet.
    public PublicPgpKey PublicKey => _publicKey ??= new PublicPgpKey(Data, DataIsArmored);

    internal ReadOnlyMemory<byte> Passphrase { get; }

    public static PrivatePgpKey FromArmored(string armoredKeyBlock, ReadOnlyMemory<byte> passphrase)
    {
        return new(Encoding.ASCII.GetBytes(armoredKeyBlock), passphrase, true);
    }
}
