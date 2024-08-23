namespace Proton.Security.Cryptography;

public sealed class IncorrectPassphraseException : CryptographicException
{
    public IncorrectPassphraseException(string message)
        : base(message)
    {
    }

    public IncorrectPassphraseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public IncorrectPassphraseException()
    {
    }
}
