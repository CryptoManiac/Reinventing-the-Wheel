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

        public static byte Interpolation(ReadOnlySpan<SharePoint> points)
        {
            ShareByte secret = 0;

            for (int i = 0; i < points.Length; ++i)
            {
                ShareByte term = 1;
                for (int j = 0; j < points.Length; ++j)
                {
                    if (i == j) continue;
                    term *= points[j].X / (points[j].X ^ points[i].X);
                }
                term *= points[i].Y;
                secret ^= term;
            }
            return secret;
        }
    }
}

