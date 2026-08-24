#include <stdint.h>
#include <string.h>

#include "dump.h"

/*
 * Decode one UTF-8 scalar at p (with `avail` bytes left). Returns 1 and sets
 * *cp / *len for a well-formed, complete, non-overlong, non-surrogate scalar;
 * otherwise returns 0 with *len = 1 (a truncated sequence at the end of the
 * buffer, a stray continuation byte, or an invalid encoding).
 */
static int utf8_decode(const unsigned char *p, size_t avail, uint32_t *cp, int *len)
{
    unsigned char c;
    uint32_t v;
    uint32_t min;
    int n;
    int i;

    if (avail == 0) {
        *len = 1;
        return 0;
    }
    c = p[0];
    if (c < 0x80) {
        *cp = c;
        *len = 1;
        return 1;
    }
    if ((c & 0xe0) == 0xc0) {
        n = 2;
        v = c & 0x1f;
        min = 0x80;
    } else if ((c & 0xf0) == 0xe0) {
        n = 3;
        v = c & 0x0f;
        min = 0x800;
    } else if ((c & 0xf8) == 0xf0) {
        n = 4;
        v = c & 0x07;
        min = 0x10000;
    } else {
        *len = 1;
        return 0;
    }
    if ((size_t)n > avail) {
        *len = 1;
        return 0;
    }
    for (i = 1; i < n; ++i) {
        if ((p[i] & 0xc0) != 0x80) {
            *len = 1;
            return 0;
        }
        v = (v << 6) | (p[i] & 0x3f);
    }
    if (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) {
        *len = 1;
        return 0;
    }
    *cp = v;
    *len = n;
    return 1;
}

/*
 * A scalar that must never be echoed to the gutter: it either does nothing
 * visible or can hijack the terminal (C0/C1 controls, DEL, line/paragraph
 * separators, zero-width and directional-format characters, the BOM). Such a
 * scalar is shown as '.' instead.
 */
static int cp_is_unsafe(uint32_t cp)
{
    if (cp < 0x20 || cp == 0x7f) { /* C0 controls + DEL */
        return 1;
    }
    if (cp >= 0x80 && cp <= 0x9f) { /* C1 controls */
        return 1;
    }
    if (cp == 0x2028 || cp == 0x2029) { /* line / paragraph separators */
        return 1;
    }
    if (cp >= 0x200b && cp <= 0x200f) { /* zero-width + LRM/RLM */
        return 1;
    }
    if (cp >= 0x202a && cp <= 0x202e) { /* bidi embeddings / overrides */
        return 1;
    }
    if (cp >= 0x2066 && cp <= 0x2069) { /* bidi isolates */
        return 1;
    }
    if (cp == 0xfeff) { /* BOM / ZWNBSP */
        return 1;
    }
    if (cp >= 0xfff9 && cp <= 0xfffb) { /* interlinear annotation */
        return 1;
    }
    return 0;
}

/*
 * Terminal display width of a scalar (0, 1 or 2 columns), after Markus Kuhn's
 * public-domain wcwidth: combining marks are zero-width, East-Asian Wide and
 * Fullwidth characters (CJK ideographs, Hangul syllables, kana, ...) are two
 * columns, everything else one. Locale-independent, so it works in a bare
 * static initramfs where setlocale() has no data. Returns -1 for a control.
 */
static int mk_wcwidth(uint32_t ucs)
{
    static const struct {
        uint32_t first, last;
    } combining[] = {
        { 0x0300, 0x036f },
        { 0x0483, 0x0489 },
        { 0x0591, 0x05bd },
        { 0x05bf, 0x05bf },
        { 0x05c1, 0x05c2 },
        { 0x05c4, 0x05c5 },
        { 0x05c7, 0x05c7 },
        { 0x0610, 0x061a },
        { 0x064b, 0x065f },
        { 0x0670, 0x0670 },
        { 0x06d6, 0x06dc },
        { 0x06df, 0x06e4 },
        { 0x06e7, 0x06e8 },
        { 0x06ea, 0x06ed },
        { 0x0711, 0x0711 },
        { 0x0730, 0x074a },
        { 0x07a6, 0x07b0 },
        { 0x07eb, 0x07f3 },
        { 0x0901, 0x0902 },
        { 0x093c, 0x093c },
        { 0x0941, 0x0948 },
        { 0x094d, 0x094d },
        { 0x0951, 0x0954 },
        { 0x0962, 0x0963 },
        { 0x0e31, 0x0e31 },
        { 0x0e34, 0x0e3a },
        { 0x0e47, 0x0e4e },
        { 0x1dc0, 0x1dff },
        { 0x20d0, 0x20f0 },
        { 0xfe20, 0xfe23 },
    };
    int lo = 0;
    int hi = (int)(sizeof(combining) / sizeof(combining[0])) - 1;

    if (ucs == 0) {
        return 0;
    }
    if (ucs < 32 || (ucs >= 0x7f && ucs < 0xa0)) {
        return -1;
    }

    while (lo <= hi) { /* zero-width combining marks */
        int mid = (lo + hi) / 2;

        if (ucs < combining[mid].first) {
            hi = mid - 1;
        } else if (ucs > combining[mid].last) {
            lo = mid + 1;
        } else {
            return 0;
        }
    }

    return 1 +
           (ucs >= 0x1100 &&
            (ucs <= 0x115f || /* Hangul Jamo */
             ucs == 0x2329 || ucs == 0x232a ||
             (ucs >= 0x2e80 && ucs <= 0xa4cf && ucs != 0x303f) || /* CJK .. Yi */
             (ucs >= 0xac00 && ucs <= 0xd7a3) ||                  /* Hangul Syllables */
             (ucs >= 0xf900 && ucs <= 0xfaff) ||                  /* CJK Compat */
             (ucs >= 0xfe10 && ucs <= 0xfe19) ||                  /* Vertical forms */
             (ucs >= 0xfe30 && ucs <= 0xfe6f) ||                  /* CJK Compat Forms */
             (ucs >= 0xff00 && ucs <= 0xff60) ||                  /* Fullwidth Forms */
             (ucs >= 0xffe0 && ucs <= 0xffe6) ||
             (ucs >= 0x20000 && ucs <= 0x2fffd) ||
             (ucs >= 0x30000 && ucs <= 0x3fffd)));
}

/*
 * Render bytes in the hexdump -C shape: an 8-hex offset column relative to the
 * start address (the absolute VA/PA are printed once in the banner above, so the
 * rows stay pipe- and xxd-comparable), 16 bytes split 8 + 8, then a text gutter
 * of a fixed 16 display columns. In ASCII mode each printable byte prints itself
 * and the rest print '.'. In CJK mode the gutter decodes UTF-8 across the whole
 * buffer (so a multi-byte character straddling a 16-byte line still shows), each
 * printable scalar occupies its true display width, unsafe scalars collapse to
 * '.', and every line is padded to the same 16 columns so the borders align.
 */
void dump_bytes(FILE *out, const unsigned char *b, size_t n, int cjk,
                int cols, int group, int upper)
{
    const char *offfmt = upper ? "%08llX  " : "%08llx  ";
    const char *hexfmt = upper ? "%02X " : "%02x ";
    size_t off;
    size_t skip = 0; /* CJK: leading bytes already consumed by a prior glyph */

    for (off = 0; off < n; off += (size_t)cols) {
        size_t linelen = (n - off < (size_t)cols) ? (n - off) : (size_t)cols;
        int k;

        fprintf(out, offfmt, (unsigned long long)off);
        for (k = 0; k < cols; ++k) {
            if ((size_t)k < linelen) {
                fprintf(out, hexfmt, b[off + k]);
            } else {
                fputs("   ", out);
            }
            if (group > 0 && (k + 1) % group == 0 && k + 1 < cols) {
                fputc(' ', out);
            }
        }
        fputc('|', out);

        if (!cjk) {
            for (k = 0; (size_t)k < linelen; ++k) {
                unsigned char c = b[off + k];

                fputc((c >= 0x20 && c <= 0x7e) ? (int)c : '.', out);
            }
            for (k = (int)linelen; k < cols; ++k) {
                fputc(' ', out);
            }
        } else {
            size_t pos = off + (skip < linelen ? skip : linelen);
            size_t next_skip = 0;
            int col = 0;

            skip = 0;
            while (pos < off + linelen && col < cols) {
                uint32_t cp;
                int len;
                int w;

                if (!utf8_decode(b + pos, n - pos, &cp, &len)) {
                    fputc('.', out);
                    ++col;
                    pos += 1;
                    continue;
                }
                w = mk_wcwidth(cp);
                if (cp_is_unsafe(cp) || w <= 0 || col + w > cols) {
                    fputc('.', out);
                    ++col;
                } else {
                    fwrite(b + pos, 1, (size_t)len, out);
                    col += w;
                }
                pos += len;
                if (pos > off + linelen) {
                    next_skip = pos - (off + linelen);
                }
            }
            for (; col < cols; ++col) {
                fputc(' ', out);
            }
            skip = next_skip;
        }

        fputs("|\n", out);
    }
}
