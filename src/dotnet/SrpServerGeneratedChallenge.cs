namespace Proton.Security;

public sealed record SrpServerGeneratedChallenge(int Version, ReadOnlyMemory<byte> Ephemeral, int BitLength = 2048);
