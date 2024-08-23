using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;

namespace Proton.Security.Cryptography.GopenPgp;

public sealed class SigningCapablePgpKeyAndDataPacketProducer : PgpKeyAndDataPacketProducer, ISigningCapablePgpDataPacketProducer
{
    private readonly PrivatePgpKey _privateKey;
    private readonly PublicPgpKey? _publicKeyForSignatureEncryption;

    public SigningCapablePgpKeyAndDataPacketProducer(PgpSessionKey sessionKey, PrivatePgpKey privateKey, Func<DateTimeOffset> getTimestampFunction)
        : base(sessionKey, getTimestampFunction)
    {
        _privateKey = privateKey;
    }

    public SigningCapablePgpKeyAndDataPacketProducer(
        PgpSessionKey sessionKey,
        PrivatePgpKey privateKey,
        PublicPgpKey publicKeyForSignatureEncryption,
        Func<DateTimeOffset> getTimestampFunction)
        : this(sessionKey, privateKey, getTimestampFunction)
    {
        _publicKeyForSignatureEncryption = publicKeyForSignatureEncryption;
    }

    public bool CanEncryptSignature => _publicKeyForSignatureEncryption is not null;

    public Stream GetEncryptingAndSigningStream(PlainDataSource plainDataSource)
    {
        return new EncryptingStream(
            (plainData, name) => InteropEncryptionInput.Create(null, SessionKey, null, plainData, PgpArmoring.None, PgpCompression.None, name),
            () => InteropSignatureInput.Create(_privateKey, default),
            plainDataSource,
            GetTimestampFunction);
    }

    public (Stream EncryptingStream, Stream SignatureStream) GetEncryptingAndSignatureStreams(
        PlainDataSource plainDataSource,
        DetachedSignatureParameters detachedSignatureParameters)
    {
        return EncryptingStream.CreateWithSignatureStream(
            (plainData, name) => InteropEncryptionInput.Create(null, SessionKey, null, plainData, PgpArmoring.None, PgpCompression.None, name),
            () => CreateInteropSignatureInput(detachedSignatureParameters),
            plainDataSource,
            GetTimestampFunction);
    }

    public Stream GetSignatureStream(PlainDataSource plainDataSource, DetachedSignatureParameters detachedSignatureParameters)
    {
        return new SignatureStream(plainDataSource, () => CreateInteropSignatureInput(detachedSignatureParameters), GetTimestampFunction);
    }

    private Disposable<InteropSignatureInput> CreateInteropSignatureInput(DetachedSignatureParameters detachedSignatureParameters)
    {
        if (detachedSignatureParameters.Security == PgpSignatureSecurity.Encrypted && _publicKeyForSignatureEncryption is null)
        {
            throw new InvalidOperationException("A signature stream that encrypts the signature cannot be provided without a public key.");
        }

        var publicKeyForSignatureEncryption = detachedSignatureParameters.Security == PgpSignatureSecurity.Encrypted
            ? _publicKeyForSignatureEncryption
            : null;

        var mustArmor = detachedSignatureParameters.Armoring == PgpArmoring.Ascii;

        return InteropSignatureInput.Create(_privateKey, (publicKeyForSignatureEncryption, mustArmor));
    }
}
