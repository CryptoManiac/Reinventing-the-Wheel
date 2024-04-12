using System.Runtime.InteropServices;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;


/// <summary>
/// Ed25519 signature verification context
/// </summary>
[StructLayout(LayoutKind.Explicit)]
public unsafe struct EDP_SIGV_CTX{

    #region Data storage
    [FieldOffset(0)]
    private unsafe fixed U8 _pk[32];
    [FieldOffset(32)] 
    private unsafe fixed U8 _q_table[16 * PE_POINT.TypeByteSz];

    /// <summary>
    /// Type size in bytes
    /// </summary>
    public const int TypeByteSz = 32 + 16 * PE_POINT.TypeByteSz;

    #endregion

    /// <summary>
    /// Implementation of the signature challenge calculation R = H(R, A, m)
    /// </summary>
    [FieldOffset(64)]
    internal unsafe delegate*<Span<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, void> _HRAM_IMPL_;

    #region Access wrappers
    private unsafe Span<U8> pk
    {
        get
        {
            fixed (U8* ptr = &_pk[0])
            {
                return new(ptr, 32);
            }
        }
    }

    private unsafe Span<PE_POINT> q_table
    {
        get
        {
            fixed (U8* ptr = &_q_table[0])
            {
                return new(ptr, 16);
            }
        }
    }

    /// <summary>
    /// Signature challenge calculation R = H(R, A, m)
    /// </summary>
    private unsafe void HRAM(Span<U8> hram, ReadOnlySpan<U8> R, ReadOnlySpan<U8> A, ReadOnlySpan<U8> m) => _HRAM_IMPL_(hram, R, A, m);
    #endregion

    private void QTABLE_SET(ref Ext_POINT T, in Ext_POINT Q, int d, int s)
    {
        ECP.edp_AddPoint(ref T, Q, q_table[s]);
        ECP.edp_ExtPoint2PE(ref q_table[d], T);
    }

    /// <summary>
    /// Initialize verification context
    /// </summary>
    /// <param name="publicKey">[32 bytes] public key</param>
    /// <param name="hram_fn">HRAM function address</param>
    public unsafe EDP_SIGV_CTX(ReadOnlySpan<U8> publicKey, delegate*<Span<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, void> hram_fn)
    {
        uint i;
        Ext_POINT Q, T;

        publicKey[0 .. 32].CopyTo(pk);

        i = ECP.ecp_DecodeInt(Q.y, publicKey);
        ECP.ed25519_CalculateX(Q.x, Q.y, ~i); /* Invert parity for -Q */
        ECP.ecp_MulMod(Q.t, Q.x, Q.y);
        ECP.ecp_SetValue(Q.z, 1);

        /* pre-compute q-table */

        /* Calculate: Q0=Q, Q1=(2^64)*Q, Q2=(2^128)*Q, Q3=(2^192)*Q */

        ECP.ecp_SetValue(q_table[0].YpX, 1); /* -- -- -- -- */
        ECP.ecp_SetValue(q_table[0].YmX, 1);
        ECP.ecp_SetValue(q_table[0].T2d, 0);
        ECP.ecp_SetValue(q_table[0].Z2, 2);

        ECP.edp_ExtPoint2PE(ref q_table[1], Q); /* -- -- -- q0 */

        for (i = 0; i < 64; i++)
        {
            ECP.edp_DoublePoint(ref Q);
        }

        ECP.edp_ExtPoint2PE(ref q_table[2], Q); /* -- -- q1 -- */
        QTABLE_SET(ref T, Q, 3, 1); /* -- -- q1 q0 */

        do
        {
            ECP.edp_DoublePoint(ref Q);
        } while (++i < 128);

        ECP.edp_ExtPoint2PE(ref q_table[4], Q); /* -- q2 -- -- */
        QTABLE_SET(ref T, Q, 5, 1); /* -- q2 -- q0 */
        QTABLE_SET(ref T, Q, 6, 2); /* -- q2 q1 -- */
        QTABLE_SET(ref T, Q, 7, 3); /* -- q2 q1 q0 */

        do
        {
            ECP.edp_DoublePoint(ref Q);
        } while (++i < 192);

        ECP.edp_ExtPoint2PE(ref q_table[8], Q); /* q3 -- -- -- */
        QTABLE_SET(ref T, Q, 9, 1); /* q3 -- -- q0 */
        QTABLE_SET(ref T, Q, 10, 2); /* q3 -- q1 -- */
        QTABLE_SET(ref T, Q, 11, 3); /* q3 -- q1 q0 */
        QTABLE_SET(ref T, Q, 12, 4); /* q3 q2 -- -- */
        QTABLE_SET(ref T, Q, 13, 5); /* q3 q2 -- q0 */
        QTABLE_SET(ref T, Q, 14, 6); /* q3 q2 q1 -- */
        QTABLE_SET(ref T, Q, 15, 7); /* q3 q2 q1 q0 */

        // Set HRAM implementation
        _HRAM_IMPL_ = hram_fn;
    }

    /// <summary>
    /// Verify ED25519 signature
    /// </summary>
    /// <param name="R">IN: [32 bytes] signature R</param>
    /// <param name="S">IN: [32 bytes] signature S</param>
    /// <param name="msg">IN: message to sign</param>
    /// <returns></returns>
    public bool Check(ReadOnlySpan<U8> R, ReadOnlySpan<U8> S, ReadOnlySpan<U8> msg)
    {
        /* h = H(enc(R) + pk + m)  mod BPO */
        Span<U8> hram_raw = stackalloc U8[64];
        HRAM(hram_raw,
            R[0 .. 32], /* enc(R) */
            pk,
            msg);

        Span<U_WORD> hram = stackalloc U_WORD[Const.K_WORDS];
        ECP.eco_DigestToWords(hram, hram_raw);
        ECP.eco_Mod(hram);

        /* T = s*P + hram*(-Q) = (s - hram*a)*P = r*P = R */

        Span<U_WORD> s = stackalloc U_WORD[Const.K_WORDS];
        ECP.ecp_BytesToWords(s, S[0 .. 32]);

        Affine_POINT T;
        ECP.edp_PolyPointMultiply(ref T, s, hram, q_table);


        Span<U8> check_R = stackalloc U8[32];
        ECP.ed25519_PackPoint(check_R, T.y, T.x[0]);

        return ECP.Equals(check_R, R, 32);
    }
}
