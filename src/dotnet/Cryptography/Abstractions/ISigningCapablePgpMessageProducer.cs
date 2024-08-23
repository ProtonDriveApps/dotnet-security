namespace Proton.Security.Cryptography.Abstractions;

public interface ISigningCapablePgpMessageProducer : IPgpMessageProducer, IPgpSignatureProducer
{
    Stream GetEncryptingAndSigningStream(
        PlainDataSource plainDataSource,
        PgpArmoring messageArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None);

    (Stream EncryptingStream, Stream SignatureStream) GetEncryptingAndSignatureStreams(
        PlainDataSource plainDataSource,
        DetachedSignatureParameters detachedSignatureParameters,
        PgpArmoring messageArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None);

    (Stream EncryptingStream, Stream SignatureStream, Task<PgpSessionKey> SessionKey) GetEncryptingAndSignatureStreamsWithSessionKey(
        PlainDataSource plainDataSource,
        DetachedSignatureParameters detachedSignatureParameters,
        PgpArmoring messageArmoring = PgpArmoring.None,
        PgpCompression compression = PgpCompression.None);
}
