namespace Proton.Security.Cryptography.Abstractions;

public interface IPgpMessageProducer
{
    Stream GetEncryptingStream(
        PlainDataSource plainDataSource,
        PgpArmoring outputArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None);

    (Stream Stream, Task<PgpSessionKey> SessionKey) GetEncryptingStreamWithSessionKey(
        PlainDataSource plainDataSource,
        PgpArmoring outputArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None);
}
