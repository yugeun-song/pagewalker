#include "dump.h"

#include <stdint.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/*
 * Decode one UTF-8 scalar at `bytes` (with `available` bytes left). Returns 1 and
 * sets *mut_code_point / *mut_len for a well-formed, complete, non-overlong,
 * non-surrogate scalar; otherwise returns 0 with *mut_len = 1 (a truncated
 * sequence at the end of the buffer, a stray continuation byte, or an invalid
 * encoding).
 */
static int decode_utf8(uint32_t *const mut_code_point, int *const mut_len,
                       const unsigned char *const bytes, size_t available)
{
    if (available == 0) {
        *mut_len = 1;
        return 0;
    }

    unsigned char lead = bytes[0];

    if (lead < 0x80) {
        *mut_code_point = lead;
        *mut_len = 1;
        return 1;
    }

    uint32_t code_point;
    uint32_t min_code_point;
    int length;

    if ((lead & 0xE0) == 0xC0) {
        length = 2;
        code_point = lead & 0x1F;
        min_code_point = 0x80;
    } else if ((lead & 0xF0) == 0xE0) {
        length = 3;
        code_point = lead & 0x0F;
        min_code_point = 0x800;
    } else if ((lead & 0xF8) == 0xF0) {
        length = 4;
        code_point = lead & 0x07;
        min_code_point = 0x10000;
    } else {
        *mut_len = 1;
        return 0;
    }
    if ((size_t)length > available) {
        *mut_len = 1;
        return 0;
    }
    for (int i = 1; i < length; ++i) {
        if ((bytes[i] & 0xC0) != 0x80) {
            *mut_len = 1;
            return 0;
        }
        code_point = (code_point << 6) | (bytes[i] & 0x3F);
    }
    if (code_point < min_code_point || code_point > 0x10FFFF ||
        (code_point >= 0xD800 && code_point <= 0xDFFF)) {
        *mut_len = 1;
        return 0;
    }
    *mut_code_point = code_point;
    *mut_len = length;
    return 1;
}

/*
 * A scalar that must never be echoed to the gutter: it either does nothing
 * visible or can hijack the terminal (C0/C1 controls, DEL, line/paragraph
 * separators, zero-width and directional-format characters, the BOM). Such a
 * scalar is shown as '.' instead.
 */
static int is_unsafe_code_point(uint32_t code_point)
{
    if (code_point < 0x20 || code_point == 0x7F) { /* C0 controls + DEL */
        return 1;
    }
    if (code_point >= 0x80 && code_point <= 0x9F) { /* C1 controls */
        return 1;
    }
    if (code_point == 0x2028 || code_point == 0x2029) { /* line / paragraph separators */
        return 1;
    }
    if (code_point >= 0x200B && code_point <= 0x200F) { /* zero-width + LRM/RLM */
        return 1;
    }
    if (code_point >= 0x202A && code_point <= 0x202E) { /* bidi embeddings / overrides */
        return 1;
    }
    if (code_point >= 0x2066 && code_point <= 0x2069) { /* bidi isolates */
        return 1;
    }
    if (code_point == 0xFEFF) { /* BOM / ZWNBSP */
        return 1;
    }
    if (code_point >= 0xFFF9 && code_point <= 0xFFFB) { /* interlinear annotation */
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
static int compute_wcwidth(uint32_t code_point)
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

    if (code_point == 0) {
        return 0;
    }
    if (code_point < 32 || (code_point >= 0x7F && code_point < 0xA0)) {
        return -1;
    }

    int low = 0;
    int high = (int)ARRAY_SIZE(s_combining) - 1;

    while (low <= high) { /* zero-width combining marks */
        int middle = (low + high) / 2;

        if (code_point < s_combining[middle].first) {
            high = middle - 1;
        } else if (code_point > s_combining[middle].last) {
            low = middle + 1;
        } else {
            return 0;
        }
    }

    return 1 +
           (code_point >= 0x1100 &&
            (code_point <= 0x115F || /* Hangul Jamo */
             code_point == 0x2329 || code_point == 0x232A ||
             (code_point >= 0x2E80 && code_point <= 0xA4CF && code_point != 0x303F) || /* CJK .. Yi */
             (code_point >= 0xAC00 && code_point <= 0xD7A3) || /* Hangul Syllables */
             (code_point >= 0xF900 && code_point <= 0xFAFF) || /* CJK Compat */
             (code_point >= 0xFE10 && code_point <= 0xFE19) || /* Vertical forms */
             (code_point >= 0xFE30 && code_point <= 0xFE6F) || /* CJK Compat Forms */
             (code_point >= 0xFF00 && code_point <= 0xFF60) || /* Fullwidth Forms */
             (code_point >= 0xFFE0 && code_point <= 0xFFE6) ||
             (code_point >= 0x20000 && code_point <= 0x2FFFD) ||
             (code_point >= 0x30000 && code_point <= 0x3FFFD)));
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
void dump_bytes(FILE *const mut_out, const unsigned char *const bytes, size_t size, int is_cjk,
                int cols, int group, int is_uppercase)
{
    const char *offset_format = (is_uppercase != 0) ? "%08llX  " : "%08llx  ";
    const char *byte_format = (is_uppercase != 0) ? "%02X " : "%02x ";
    size_t skip = 0; /* CJK: leading bytes already consumed by a prior glyph */

    for (size_t offset = 0; offset < size; offset += (size_t)cols) {
        size_t line_length = (size - offset < (size_t)cols) ? (size - offset) : (size_t)cols;

        fprintf(mut_out, offset_format, (unsigned long long)offset);
        for (int k = 0; k < cols; ++k) {
            if ((size_t)k < line_length) {
                fprintf(mut_out, byte_format, bytes[offset + (size_t)k]);
            } else {
                fputs("   ", mut_out);
            }
            if (group > 0 && (k + 1) % group == 0 && k + 1 < cols) {
                fputc(' ', mut_out);
            }
        }
        fputc('|', mut_out);

        if (is_cjk == 0) {
            for (int k = 0; (size_t)k < line_length; ++k) {
                unsigned char byte = bytes[offset + (size_t)k];

                fputc((byte >= 0x20 && byte <= 0x7E) ? (int)byte : '.', mut_out);
            }
            for (int k = (int)line_length; k < cols; ++k) {
                fputc(' ', mut_out);
            }
        } else {
            size_t pos = offset + ((skip < line_length) ? skip : line_length);
            size_t next_skip = 0;
            int column = 0;

            skip = 0;
            while (pos < offset + line_length && column < cols) {
                uint32_t code_point;
                int length;

                if (decode_utf8(&code_point, &length, bytes + pos, size - pos) == 0) {
                    fputc('.', mut_out);
                    ++column;
                    pos += 1;
                    continue;
                }

                int width = compute_wcwidth(code_point);

                if (is_unsafe_code_point(code_point) != 0 || width <= 0 || column + width > cols) {
                    fputc('.', mut_out);
                    ++column;
                } else {
                    fwrite(bytes + pos, 1, (size_t)length, mut_out);
                    column += width;
                }
                pos += (size_t)length;
                if (pos > offset + line_length) {
                    next_skip = pos - (offset + line_length);
                }
            }
            for (; column < cols; ++column) {
                fputc(' ', mut_out);
            }
            skip = next_skip;
        }

        fputs("|\n", mut_out);
    }
}
