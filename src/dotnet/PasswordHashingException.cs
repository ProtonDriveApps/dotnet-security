namespace Proton.Security;

public sealed class PasswordHashingException : Exception
{
    public PasswordHashingException()
    {
    }

    public PasswordHashingException(string? message)
        : base(message)
    {
    }

    public PasswordHashingException(string? message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
