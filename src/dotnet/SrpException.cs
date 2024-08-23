namespace Proton.Security;

public sealed class SrpException : Exception
{
    public SrpException()
    {
    }

    public SrpException(string? message)
        : base(message)
    {
    }

    public SrpException(string? message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
