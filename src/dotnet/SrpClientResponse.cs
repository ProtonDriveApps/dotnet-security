namespace Proton.Security;

public sealed record SrpClientResponse(byte[] ClientProof, SrpClientGeneratedChallenge ClientGeneratedChallenge);
