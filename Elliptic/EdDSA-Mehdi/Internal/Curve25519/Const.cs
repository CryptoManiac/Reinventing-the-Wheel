using EdDSA_Mehdi.Internal.BaseTypes;

namespace EdDSA_Mehdi.Internal.Curve25519;

/// <summary>
/// Conversion functions and constants
/// </summary>
public static partial class Const
{
    public const int K_BYTES = 32;
    public const int K_WORDS = (K_BYTES / sizeof(U_WORD));

    /// <summary>
    /// 2*d
    /// </summary>
    public static readonly M256 _w_2d = new(0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A, 0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC);

    /// <summary>
    /// 1/d
    /// </summary>
    public static readonly M256 _w_di = new(0xCDC9F843, 0x25E0F276, 0x4279542E, 0x0B5DD698, 0xCDB9CF66, 0x2B162114, 0x14D5CE43, 0x40907ED2);

    /// <summary>
    /// X coordinate of base point
    /// </summary>
    public static M256V_U8 ecp_BasePoint = new(
        9, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0
    );

    public static M256 _w_P = new(
    0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF
);

    /// <summary>
    /// Maximum number of prime p that fits into 256-bits
    /// </summary>
    public static M256 _w_maxP = new(
        0xFFFFFFDA, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    );

    /// <summary>
    /// n * BPO
    /// </summary>
    public static readonly M256[] _w_NxBPO = new M256[16]
    {
        new(0, 0, 0, 0, 0, 0, 0, 0),
        new(0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0, 0, 0, 0x10000000),
        new(0xB9EBA7DA, 0xB024C634, 0x45EF39AC, 0x29BDF3BD, 0, 0, 0, 0x20000000),
        new(0x16E17BC7, 0x0837294F, 0xE8E6D683, 0x3E9CED9B, 0, 0, 0, 0x30000000),
        new(0x73D74FB4, 0x60498C69, 0x8BDE7359, 0x537BE77A, 0, 0, 0, 0x40000000),
        new(0xD0CD23A1, 0xB85BEF83, 0x2ED6102F, 0x685AE159, 0, 0, 0, 0x50000000),
        new(0x2DC2F78E, 0x106E529E, 0xD1CDAD06, 0x7D39DB37, 0, 0, 0, 0x60000000),
        new(0x8AB8CB7B, 0x6880B5B8, 0x74C549DC, 0x9218D516, 0, 0, 0, 0x70000000),
        new(0xE7AE9F68, 0xC09318D2, 0x17BCE6B2, 0xA6F7CEF5, 0, 0, 0, 0x80000000),
        new(0x44A47355, 0x18A57BED, 0xBAB48389, 0xBBD6C8D3, 0, 0, 0, 0x90000000),
        new(0xA19A4742, 0x70B7DF07, 0x5DAC205F, 0xD0B5C2B2, 0, 0, 0, 0xA0000000),
        new(0xFE901B2F, 0xC8CA4221, 0x00A3BD35, 0xE594BC91, 0, 0, 0, 0xB0000000),
        new(0x5B85EF1C, 0x20DCA53C, 0xA39B5A0C, 0xFA73B66F, 0, 0, 0, 0xC0000000),
        new(0xB87BC309, 0x78EF0856, 0x4692F6E2, 0x0F52B04E, 1, 0, 0, 0xD0000000),
        new(0x157196F6, 0xD1016B71, 0xE98A93B8, 0x2431AA2C, 1, 0, 0, 0xE0000000),
        new(0x72676AE3, 0x2913CE8B, 0x8C82308F, 0x3910A40B, 1, 0, 0, 0xF0000000)
    };

    /// <summary>
    /// sqrt(-1)
    /// </summary>
    public static readonly M256 _w_I = new(0x4A0EA0B0, 0xC4EE1B27, 0xAD2FE478, 0x2F431806, 0x3DFBD7A7, 0x2B4D0099,
        0x4FC1DF0B, 0x2B832480);


    public static readonly M256 _w_d = new(0x135978A3, 0x75EB4DCA, 0x4141D8AB, 0x00700A4D, 0x7779E898, 0x8CC74079,
        0x2B6FFE73, 0x52036CEE);

    public static ReadOnlySpan<U32> _w_BPO => _w_NxBPO[1].words;
    public static ReadOnlySpan<U32> _w_Zero => _w_base_folding8[0].T2d;
    public static ReadOnlySpan<U32> _w_One => _w_base_folding8[0].YpX;
}
