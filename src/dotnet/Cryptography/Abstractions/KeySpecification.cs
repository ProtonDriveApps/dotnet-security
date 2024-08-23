namespace Proton.Security.Cryptography.Abstractions;

public readonly struct KeySpecification
{
    private KeySpecification(KeyType type, int? bits)
    {
        Type = type;
        Bits = bits;
    }

    public KeyType Type { get; }
    public int? Bits { get; }

    public static KeySpecification Rsa(int bits) => new(KeyType.Rsa, bits);
    public static KeySpecification X25519() => new(KeyType.X25519, default);
}
