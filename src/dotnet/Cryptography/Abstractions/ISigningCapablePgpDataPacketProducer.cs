namespace Proton.Security.Cryptography.Abstractions;

public interface ISigningCapablePgpDataPacketProducer : IPgpDataPacketProducer, IPgpSignatureProducer
{
    bool CanEncryptSignature { get; }

    Stream GetEncryptingAndSigningStream(PlainDataSource plainDataSource);

    (Stream EncryptingStream, Stream SignatureStream) GetEncryptingAndSignatureStreams(
        PlainDataSource plainDataSource,
        DetachedSignatureParameters detachedSignatureParameters);
}
