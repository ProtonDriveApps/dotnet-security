using Proton.Security.Cryptography.Abstractions;
using Proton.Security.Cryptography.GopenPgp.Interop;
using Proton.Security.Interop;
using Proton.Security.InteropServices;

namespace Proton.Security.Cryptography.GopenPgp;

public class PgpKeyAndDataPacketProducer : IPgpDataPacketProducer, IPgpKeyPacketProducer
{
    public PgpKeyAndDataPacketProducer(PgpSessionKey sessionKey, Func<DateTimeOffset> getTimestampFunction)
    {
        SessionKey = sessionKey;
        GetTimestampFunction = getTimestampFunction;
    }

    protected PgpSessionKey SessionKey { get; }
    protected Func<DateTimeOffset> GetTimestampFunction { get; }

    public Stream GetDataPacketStream(PlainDataSource plainDataSource)
    {
        return new EncryptingStream(
            (plainData, name) => InteropEncryptionInput.Create(null, SessionKey, null, plainData, PgpArmoring.None, PgpCompression.None, name),
            plainDataSource,
            GetTimestampFunction);
    }

    public ReadOnlyMemory<byte> GetKeyPacket(PublicPgpKey publicKey)
    {
        return GetKeyPacket(
            interopSessionKey =>
            {
                using var interopPublicKey = publicKey.ToInterop();
                return GopenPgpInterop.EncryptSessionKey(interopSessionKey, interopPublicKey.Value, IntPtr.Zero);
            });
    }

    public ReadOnlyMemory<byte> GetKeyPacket(SecureString password)
    {
        return GetKeyPacket(
            interopSessionKey =>
            {
                using var interopPassword = password.ToInteropArray();
                return GopenPgpInterop.EncryptSessionKey(interopSessionKey, IntPtr.Zero, interopPassword.Value);
            });
    }

    private ReadOnlyMemory<byte> GetKeyPacket(Func<InteropSessionKey, InteropArrayResultHandle> interopFunc)
    {
        InteropArrayResultHandle? interopResultHandle;
        using (var interopSessionKey = SessionKey.ToInterop())
        {
            interopResultHandle = interopFunc.Invoke(interopSessionKey.Value);
        }

        return interopResultHandle.GetBytes((_, message) => new SrpException(message));
    }
}
