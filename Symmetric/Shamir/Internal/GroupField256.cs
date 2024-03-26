namespace Wheel.Symmetric.Shamir.Internal
{
    /// <summary>
    /// TODO: Rewrite the entire thing. It's necessary to ensure the allocation-deterministic behaviour.
    /// </summary>

    internal static class GroupFieldMath
    {
        public static ShareByte Pow(ShareByte a, int b)
        {
            if (b == 0)
            {
                return 1;
            }

            ShareByte ans = Pow(a, b / 2);

            if (b % 2 != 0)
            {
                return (ans * (ans * a));
            }

            return (ans * ans);
        }

        public static byte Interpolation(Share share)
        {
            ShareByte secret = 0;

            for (int i = 0; i < share.Length; i++)
            {
                ShareByte term = 1;
                for (int j = 0; j < share.Length; j++)
                {
                    if (i == j) continue;
                    term *= (share[j].X / (share[j].X ^ share[i].X));
                }
                term *= share[i].Y;
                secret ^= term;
            }
            return secret;
        }
    }
}

