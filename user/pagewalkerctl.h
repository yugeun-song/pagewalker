#ifndef PAGEWALKERCTL_H
#define PAGEWALKERCTL_H

#include "../include/pagewalker_common.h"
#include "report.h"
#include "dump.h"
#include "symbols.h"
#include "read.h"

#define PID_MAX_FILE "/proc/sys/kernel/pid_max"
/*
 * Fallback only for when /proc/sys/kernel/pid_max is unreadable: the 64-bit
 * kernel PID_MAX_LIMIT (4 * 1024 * 1024). A modern kernel / major distro allows
 * PIDs up to this, so falling back here never falsely rejects a valid PID; the
 * kernel's own PID_MAX_LIMIT check remains the authority.
 */
#define PID_MAX_FALLBACK 4194304
#define BASE_DECIMAL 10

/* Output rendering for the byte dump, selected on the command line. */
enum out_fmt { FMT_HEX,
               FMT_RAW,
               FMT_CJK };

#endif /* PAGEWALKERCTL_H */
