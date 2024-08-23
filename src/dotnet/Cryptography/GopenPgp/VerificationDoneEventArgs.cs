namespace Proton.Security.Cryptography.GopenPgp;

internal sealed class VerificationDoneEventArgs : EventArgs
{
    public VerificationDoneEventArgs(VerificationVerdict verdict)
    {
        Verdict = verdict;
    }

    public VerificationVerdict Verdict { get; }
}
