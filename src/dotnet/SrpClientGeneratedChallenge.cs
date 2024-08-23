namespace Proton.Security;

public sealed record SrpClientGeneratedChallenge(byte[] Ephemeral, byte[] ExpectedProof);
