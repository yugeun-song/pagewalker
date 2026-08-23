#ifndef PAGEWALKER_USER_DUMP_H
#define PAGEWALKER_USER_DUMP_H

#include <stdio.h>
#include <stddef.h>

/*
 * Render bytes in the hexdump -C shape into `out`. In ASCII mode (cjk == 0)
 * each printable byte prints itself and the rest print '.'; in CJK mode
 * (cjk != 0) the text gutter decodes UTF-8 across the whole buffer and each
 * printable scalar occupies its true display width. `cols` bytes per line,
 * `group` bytes per hex group (0 disables), `upper` selects uppercase hex.
 */
void dump_bytes(FILE *out, const unsigned char *b, size_t n, int cjk,
                int cols, int group, int upper);

#endif /* PAGEWALKER_USER_DUMP_H */
