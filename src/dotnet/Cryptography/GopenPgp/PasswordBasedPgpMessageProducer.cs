using Proton.Security.Cryptography.Abstractions;

namespace Proton.Security.Cryptography.GopenPgp;

public class PasswordBasedPgpMessageProducer : PgpMessageProducerBase
{
    public PasswordBasedPgpMessageProducer(SecureString password)
    {
        Password = password;
    }

    public PasswordBasedPgpMessageProducer(SecureString password, PgpSessionKey sessionKey)
        : this(password)
    {
        SessionKey = sessionKey;
    }

    protected override PublicPgpKey? PublicKey => null;

    protected override PgpSessionKey? SessionKey { get; }

    protected override SecureString? Password { get; }

    protected override Func<DateTimeOffset> GetTimestampFunction { get; } = () => default;
}
