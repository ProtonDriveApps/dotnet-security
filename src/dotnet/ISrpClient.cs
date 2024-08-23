namespace Proton.Security;

public interface ISrpClient
{
    SrpClientResponse CalculateResponse(
        SrpServerGeneratedChallenge challenge,
        ReadOnlySpan<byte> salt,
        string signedModulus,
        string username,
        SecureString password);
}
