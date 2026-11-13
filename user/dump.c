#include "dump.h"

#include <stdint.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/*
 * Decode one UTF-8 scalar at p (with `avail` bytes left). Returns 1 and sets
 * *mut_cp / *mut_len for a well-formed, complete, non-overlong, non-surrogate
 * scalar; otherwise returns 0 with *mut_len = 1 (a truncated sequence at the end
 * of the buffer, a stray continuation byte, or an invalid encoding).
 */
static int decode_utf8(uint32_t *const mut_cp, int *const mut_len, const unsigned char *const p,
                       size_t avail)
{
    if (avail == 0) {
        *mut_len = 1;
        return 0;
    }

    unsigned char c = p[0];

    if (c < 0x80) {
        *mut_cp = c;
        *mut_len = 1;
        return 1;
    }

    uint32_t v;
    uint32_t min;
    int n;

    if ((c & 0xE0) == 0xC0) {
        n = 2;
        v = c & 0x1F;
        min = 0x80;
    } else if ((c & 0xF0) == 0xE0) {
        n = 3;
        v = c & 0x0F;
        min = 0x800;
    } else if ((c & 0xF8) == 0xF0) {
        n = 4;
        v = c & 0x07;
        min = 0x10000;
    } else {
        *mut_len = 1;
        return 0;
    }
    if ((size_t)n > avail) {
        *mut_len = 1;
        return 0;
    }
    for (int i = 1; i < n; ++i) {
        if ((p[i] & 0xC0) != 0x80) {
            *mut_len = 1;
            return 0;
        }
        v = (v << 6) | (p[i] & 0x3F);
    }
    if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) {
        *mut_len = 1;
        return 0;
    }
    *mut_cp = v;
    *mut_len = n;
    return 1;
}

/*
 * A scalar that must never be echoed to the gutter: it either does nothing
 * visible or can hijack the terminal (C0/C1 controls, DEL, line/paragraph
 * separators, zero-width and directional-format characters, the BOM). Such a
 * scalar is shown as '.' instead.
 */
static int is_unsafe_code_point(uint32_t cp)
{
    if (cp < 0x20 || cp == 0x7F) { /* C0 controls + DEL */
        return 1;
    }
    if (cp >= 0x80 && cp <= 0x9F) { /* C1 controls */
        return 1;
    }
    if (cp == 0x2028 || cp == 0x2029) { /* line / paragraph separators */
        return 1;
    }
    if (cp >= 0x200B && cp <= 0x200F) { /* zero-width + LRM/RLM */
        return 1;
    }
    if (cp >= 0x202A && cp <= 0x202E) { /* bidi embeddings / overrides */
        return 1;
    }
    if (cp >= 0x2066 && cp <= 0x2069) { /* bidi isolates */
        return 1;
    }
    if (cp == 0xFEFF) { /* BOM / ZWNBSP */
        return 1;
    }
    if (cp >= 0xFFF9 && cp <= 0xFFFB) { /* interlinear annotation */
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
static int compute_wcwidth(uint32_t ucs)
{
    static const struct {
        uint32_t first;
        uint32_t last;
    } s_combining[] = {
        { 0x0300, 0x036F },
        { 0x0483, 0x0489 },
        { 0x0591, 0x05BD },
        { 0x05BF, 0x05BF },
        { 0x05C1, 0x05C2 },
        { 0x05C4, 0x05C5 },
        { 0x05C7, 0x05C7 },
        { 0x0610, 0x061A },
        { 0x064B, 0x065F },
        { 0x0670, 0x0670 },
        { 0x06D6, 0x06DC },
        { 0x06DF, 0x06E4 },
        { 0x06E7, 0x06E8 },
        { 0x06EA, 0x06ED },
        { 0x0711, 0x0711 },
        { 0x0730, 0x074A },
        { 0x07A6, 0x07B0 },
        { 0x07EB, 0x07F3 },
        { 0x0901, 0x0902 },
        { 0x093C, 0x093C },
        { 0x0941, 0x0948 },
        { 0x094D, 0x094D },
        { 0x0951, 0x0954 },
        { 0x0962, 0x0963 },
        { 0x0E31, 0x0E31 },
        { 0x0E34, 0x0E3A },
        { 0x0E47, 0x0E4E },
        { 0x1DC0, 0x1DFF },
        { 0x20D0, 0x20F0 },
        { 0xFE20, 0xFE23 },
    };

    if (ucs == 0) {
        return 0;
    }
    if (ucs < 32 || (ucs >= 0x7F && ucs < 0xA0)) {
        return -1;
    }

    int lo = 0;
    int hi = (int)ARRAY_SIZE(s_combining) - 1;

    while (lo <= hi) { /* zero-width combining marks */
        int mid = (lo + hi) / 2;

        if (ucs < s_combining[mid].first) {
            hi = mid - 1;
        } else if (ucs > s_combining[mid].last) {
            lo = mid + 1;
        } else {
            return 0;
        }
    }

    return 1 +
           (ucs >= 0x1100 &&
            (ucs <= 0x115F || /* Hangul Jamo */
             ucs == 0x2329 || ucs == 0x232A ||
             (ucs >= 0x2E80 && ucs <= 0xA4CF && ucs != 0x303F) || /* CJK .. Yi */
             (ucs >= 0xAC00 && ucs <= 0xD7A3) || /* Hangul Syllables */
             (ucs >= 0xF900 && ucs <= 0xFAFF) || /* CJK Compat */
             (ucs >= 0xFE10 && ucs <= 0xFE19) || /* Vertical forms */
             (ucs >= 0xFE30 && ucs <= 0xFE6F) || /* CJK Compat Forms */
             (ucs >= 0xFF00 && ucs <= 0xFF60) || /* Fullwidth Forms */
             (ucs >= 0xFFE0 && ucs <= 0xFFE6) ||
             (ucs >= 0x20000 && ucs <= 0x2FFFD) ||
             (ucs >= 0x30000 && ucs <= 0x3FFFD)));
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
void dump_bytes(FILE *const mut_out, const unsigned char *const b, size_t n, int is_cjk, int cols,
                int group, int is_uppercase)
{
    const char *offfmt = (is_uppercase != 0) ? "%08llX  " : "%08llx  ";
    const char *hexfmt = (is_uppercase != 0) ? "%02X " : "%02x ";
    size_t skip = 0; /* CJK: leading bytes already consumed by a prior glyph */

    for (size_t off = 0; off < n; off += (size_t)cols) {
        size_t linelen = (n - off < (size_t)cols) ? (n - off) : (size_t)cols;

        fprintf(mut_out, offfmt, (unsigned long long)off);
        for (int k = 0; k < cols; ++k) {
            if ((size_t)k < linelen) {
                fprintf(mut_out, hexfmt, b[off + (size_t)k]);
            } else {
                fputs("   ", mut_out);
            }
            if (group > 0 && (k + 1) % group == 0 && k + 1 < cols) {
                fputc(' ', mut_out);
            }
        }
        fputc('|', mut_out);

        if (is_cjk == 0) {
            for (int k = 0; (size_t)k < linelen; ++k) {
                unsigned char c = b[off + (size_t)k];

                fputc((c >= 0x20 && c <= 0x7E) ? (int)c : '.', mut_out);
            }
            for (int k = (int)linelen; k < cols; ++k) {
                fputc(' ', mut_out);
            }
        } else {
            size_t pos = off + ((skip < linelen) ? skip : linelen);
            size_t next_skip = 0;
            int col = 0;

            skip = 0;
            while (pos < off + linelen && col < cols) {
                uint32_t cp;
                int len;

                if (decode_utf8(&cp, &len, b + pos, n - pos) == 0) {
                    fputc('.', mut_out);
                    ++col;
                    pos += 1;
                    continue;
                }

                int w = compute_wcwidth(cp);

                if (is_unsafe_code_point(cp) != 0 || w <= 0 || col + w > cols) {
                    fputc('.', mut_out);
                    ++col;
                } else {
                    fwrite(b + pos, 1, (size_t)len, mut_out);
                    col += w;
                }
                pos += (size_t)len;
                if (pos > off + linelen) {
                    next_skip = pos - (off + linelen);
                }
            }
            for (; col < cols; ++col) {
                fputc(' ', mut_out);
            }
            skip = next_skip;
        }

        fputs("|\n", mut_out);
    }
}
