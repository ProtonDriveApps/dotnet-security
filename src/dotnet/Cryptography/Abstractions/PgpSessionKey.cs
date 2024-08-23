namespace Proton.Security.Cryptography.Abstractions;

public sealed class PgpSessionKey
{
    public PgpSessionKey(ReadOnlyMemory<byte> data, string algorithmId)
    {
        Data = data;
        AlgorithmId = algorithmId;
    }

    public ReadOnlyMemory<byte> Data { get; }
    public string AlgorithmId { get; }
}
