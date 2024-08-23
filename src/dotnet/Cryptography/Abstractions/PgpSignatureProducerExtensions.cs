namespace Proton.Security.Cryptography.Abstractions;

public static class PgpSignatureProducerExtensions
{
    public static string SignWithArmor(this IPgpSignatureProducer signatureProducer, ReadOnlyMemory<byte> bytes, bool encrypted = false)
    {
        var parameters = encrypted ? DetachedSignatureParameters.ArmoredEncrypted : DetachedSignatureParameters.ArmoredPlain;

        using var plainDataSource = new PlainDataSource(bytes.AsReadOnlyStream());
        using var signatureStream = signatureProducer.GetSignatureStream(plainDataSource, parameters);
        using var streamReader = new StreamReader(signatureStream, Encoding.ASCII);
        return streamReader.ReadToEnd();
    }
}
