#ifndef USER_DUMP_H
#define USER_DUMP_H

#include <stddef.h>
#include <stdio.h>

/*
 * Render bytes in the hexdump -C shape into `mut_out`. In ASCII mode (is_cjk == 0)
 * each printable byte prints itself and the rest print '.'; in CJK mode
 * (is_cjk != 0) the text gutter decodes UTF-8 across the whole buffer and each
 * printable scalar occupies its true display width. `cols` bytes per line,
 * `group` bytes per hex group (0 disables), `is_uppercase` selects uppercase hex.
 */
void dump_bytes(FILE *const mut_out, const unsigned char *const bytes, size_t size, int is_cjk,
                int cols, int group, int is_uppercase);

#endif /* USER_DUMP_H */
