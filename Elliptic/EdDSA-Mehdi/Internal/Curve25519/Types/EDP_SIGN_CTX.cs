using System.Runtime.InteropServices;
using Wheel.Crypto.Elliptic.EllipticCommon;

namespace EdDSA_Mehdi.Internal.Curve25519.Types;

public struct EDP_SIGN_CTX
{
    private unsafe fixed U8 _sk[32];
    private unsafe fixed U8 _pk[32];
    private EDP_BLINDING_CTX blinding;

    /// <summary>
    /// Implementation of the signature challenge calculation R = H(R, A, m)
    /// </summary>
    private unsafe delegate*<Span<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, void> _HRAM_IMPL_;

    /// <summary>
    /// Implementation of signature nonce generator HMAC_sk(m) mod BPO
    /// </summary>
    private unsafe delegate*<Span<U_WORD>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, void> _HNONCE_IMPL_;

    #region Access wrappers
    /// <summary>
    /// Public key
    /// </summary>
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

    /// <summary>
    /// Secret key
    /// </summary>
    private unsafe Span<U8> sk
    {
        get
        {
            fixed (U8* ptr = &_sk[0])
            {
                return new(ptr, 32);
            }
        }
    }

    /// <summary>
    /// Call the signature challenge calculation R = H(R, A, m)
    /// </summary>
    private unsafe void HRAM(Span<U8> hram, ReadOnlySpan<U8> R, ReadOnlySpan<U8> A, ReadOnlySpan<U8> m) => _HRAM_IMPL_(hram, R, A, m);

    /// <summary>
    /// Call the implementation of nonce generator
    /// </summary>
    /// <param name="nonce"></param>
    /// <param name="m"></param>
    private unsafe void HNONCE(Span<U_WORD> nonce, ReadOnlySpan<U8> m) => _HNONCE_IMPL_(nonce, sk, m);
    #endregion

    /// <summary>
    /// Default constructor is throwing an error
    /// </summary>
    /// <exception cref="InvalidOperationException"></exception>
    public EDP_SIGN_CTX()
    {
        throw new InvalidOperationException("The default constructor must not be called");
    }

    /// <summary>
    /// Initialize new signing context
    /// </summary>
    /// <param name="sk">IN/OUT: [32 bytes] secret key</param>
    /// <param name="hram_fn">HRAM function address</param>
    public unsafe EDP_SIGN_CTX(Span<U8> sk, delegate*<Span<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, void> hram_fn, delegate*<Span<U_WORD>, ReadOnlySpan<U8>, ReadOnlySpan<U8>, void> hnonce_fn)
    {
        blinding = new();
        ECP.ed25519_CalculatePublicKey(pk, sk, blinding);
        _HRAM_IMPL_ = hram_fn;
        _HNONCE_IMPL_ = hnonce_fn;
    }

    /// <summary>
    /// Generate message signature with the user-provided signature nonce
    /// </summary>
    /// <param name="R">IN: [32 bytes] signature R</param>
    /// <param name="S">IN: [32 bytes] signature S</param>
    /// <param name="msg">IN: Message to sign</param>
    /// <param name="r">IN/OUT: Signature nonce</param>
    private void Sign(Span<U8> R, Span<U8> S, ReadOnlySpan<U8> msg, Span<U_WORD> r)
    {
        Affine_POINT R_POINT;

        /* R = r*P */
        ECP.edp_BasePointMultiply(ref R_POINT, r, blinding);
        ECP.ed25519_PackPoint(R[0 .. 32], R_POINT.y, R_POINT.x[0]); /* R part of signature */

        /* S = r + HRAM(encoded(R) + pk + m) * a  mod BPO */

        Span<U8> hram_raw = stackalloc U8[64];
        HRAM(hram_raw,
            R[0 .. 32], /* encoded(R) */
            pk, /* pk */
            msg /* m */
            );

        Span<U_WORD> t = stackalloc U_WORD[Const.K_WORDS];
        ECP.eco_DigestToWords(t, hram_raw);

        Span<U_WORD> a = stackalloc U_WORD[Const.K_WORDS];
        ECP.ecp_BytesToWords(a, sk);            /* a = secret key */
        ECP.eco_MulReduce(t, t, a);             /* h()*a */
        ECP.eco_AddReduce(t, t, r);
        ECP.eco_Mod(t);
        ECP.ecp_WordsToBytes(S[32 ..], t);  /* S part of signature */

        /* Clear sensitive data */
        ECP.ecp_SetValue(a, 0);
        ECP.ecp_SetValue(r, 0);
    }

    /// <summary>
    /// Generate deterministic message signature
    /// </summary>
    /// <param name="signature">OUT: [64 bytes] signature (R,S)</param>
    /// <param name="msg">Message to sign</param>
    public void Sign(Span<U8> R, Span<U8> S, ReadOnlySpan<U8> msg)
    {
        Span<U_WORD> r = stackalloc U_WORD[Const.K_WORDS];

        // r = HMAC_RND_sk(m) mod BPO
        HNONCE(r, msg);

        // Sign with generated nonce
        Sign(R, S, msg, r);
    }
}
