#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include "pagewalkerctl.h"

static void print_usage(const char *prog_name)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s [options] <pid> <address|symbol> [size]\n"
            "  %s [options] -k <symbol|0xaddr> [size]\n"
            "\n"
            "Walk the page tables for one address and, when a size is given, dump\n"
            "that many bytes of the mapped memory. For a process the target may be a\n"
            "hex address or the name of a global/static symbol in that process (a\n"
            "local/stack/heap variable has no symbol; pass its runtime %%p address).\n"
            "\n"
            "Options:\n"
            "  -k, --kernel        target the kernel address space; the first argument\n"
            "                      is a kernel symbol name (resolved via /proc/kallsyms)\n"
            "                      or a 0x-prefixed kernel address (e.g. _text, memblock,\n"
            "                      swapper_pg_dir)\n"
            "  -f, --format FMT    dump format: hex (default), raw, or cjk\n"
            "  -x, --hex           hexdump with an ASCII gutter (the default)\n"
            "  -c, --cjk           hexdump with a UTF-8 / CJK-aware text gutter\n"
            "  -r, --raw           raw bytes to stdout, for piping (refuses a TTY)\n"
            "  -F, --force         allow raw output even when stdout is a terminal\n"
            "  -w, --cols N        bytes per hexdump line (1..256, default 16)\n"
            "  -g, --group N       bytes per hex group; 0 disables grouping (default 8)\n"
            "  -u, --upper         uppercase hex digits\n"
            "      --no-report     print only the byte dump, not the walk report\n"
            "      --allow-mmio    permit reads of non-System-RAM (MMIO / reserved);\n"
            "                      by default such a page is refused to avoid device\n"
            "                      side effects\n"
            "  -h, --help          show this help\n"
            "\n"
            "size accepts decimal, 0x hex, 0b binary, and K/M/G suffixes (e.g. 256, 0x40, 2K).\n",
            prog_name, prog_name);
}

static unsigned int get_system_pid_max(void)
{
    FILE *f = fopen(PID_MAX_FILE, "r");
    unsigned int max = PID_MAX_FALLBACK;
    if (f) {
        if (fscanf(f, "%u", &max) != 1) {
            max = PID_MAX_FALLBACK;
        }
        fclose(f);
    }
    return max;
}

int main(int argc, char *argv[])
{
    int fd = -1;
    int ret_code = EXIT_FAILURE;
    int kernel = 0;
    int force_tty = 0;
    int have_size = 0;
    int allow_mmio = 0;
    int no_report = 0;
    int cols = 16;
    int group = 8;
    int upper = 0;
    enum out_fmt fmt = FMT_HEX;
    unsigned int pid = 0;
    unsigned long long start = 0;
    unsigned long long size = 0;
    int npos;
    int opt;

    enum { OPT_ALLOW_MMIO = 1000,
           OPT_NO_REPORT };
    static struct option long_options[] = {
        { "help", no_argument, 0, 'h' },
        { "kernel", no_argument, 0, 'k' },
        { "raw", no_argument, 0, 'r' },
        { "hex", no_argument, 0, 'x' },
        { "cjk", no_argument, 0, 'c' },
        { "force", no_argument, 0, 'F' },
        { "upper", no_argument, 0, 'u' },
        { "format", required_argument, 0, 'f' },
        { "cols", required_argument, 0, 'w' },
        { "group", required_argument, 0, 'g' },
        { "allow-mmio", no_argument, 0, OPT_ALLOW_MMIO },
        { "no-report", no_argument, 0, OPT_NO_REPORT },
        { 0, 0, 0, 0 }
    };

    while ((opt = getopt_long(argc, argv, "hkrxcFuf:w:g:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        case 'k':            kernel = 1; break;
        case 'r':            fmt = FMT_RAW; break;
        case 'x':            fmt = FMT_HEX; break;
        case 'c':            fmt = FMT_CJK; break;
        case 'F':            force_tty = 1; break;
        case 'u':            upper = 1; break;
        case OPT_ALLOW_MMIO: allow_mmio = 1; break;
        case OPT_NO_REPORT:  no_report = 1; break;
        case 'w':            {
            char *e;
            long v = strtol(optarg, &e, 10);

            if (*e != '\0' || v < 1 || v > 256) {
                fprintf(stderr, "Error: --cols must be 1..256.\n");
                return EXIT_FAILURE;
            }
            cols = (int)v;
            break;
        }
        case 'g': {
            char *e;
            long v = strtol(optarg, &e, 10);

            if (*e != '\0' || v < 0 || v > 256) {
                fprintf(stderr, "Error: --group must be 0..256 (0 = no grouping).\n");
                return EXIT_FAILURE;
            }
            group = (int)v;
            break;
        }
        case 'f':
            if (!strcmp(optarg, "hex")) {
                fmt = FMT_HEX;
            } else if (!strcmp(optarg, "raw")) {
                fmt = FMT_RAW;
            } else if (!strcmp(optarg, "cjk") || !strcmp(optarg, "utf8")) {
                fmt = FMT_CJK;
            } else {
                fprintf(stderr, "Error: unknown format '%s' (hex|raw|cjk).\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    npos = argc - optind;

    if (kernel) {
        int r;

        if (npos < 1 || npos > 2) {
            fprintf(stderr, "Error: expected <symbol|0xaddr> [size].\n");
            return EXIT_FAILURE;
        }
        r = resolve_ksym(argv[optind], &start);
        if (r == 1) {
            fprintf(stderr, "Error: symbol '%s' not found in /proc/kallsyms.\n", argv[optind]);
            return EXIT_FAILURE;
        }
        if (r == 2) {
            fprintf(stderr,
                    "Error: '%s' resolves to 0 (kernel.kptr_restrict hides symbol addresses). "
                    "Run as root; if kptr_restrict=2 even root is blocked, so lower it or pass "
                    "-k 0x<address> directly.\n",
                    argv[optind]);
            return EXIT_FAILURE;
        }
        if (r == 3) {
            fprintf(stderr, "Error: cannot read /proc/kallsyms.\n");
            return EXIT_FAILURE;
        }
        if (r == 4) {
            fprintf(stderr, "Error: invalid kernel address '%s'.\n", argv[optind]);
            return EXIT_FAILURE;
        }
        if (npos == 2) {
            if (parse_size(argv[optind + 1], &size) != 0) {
                fprintf(stderr, "Error: invalid size '%s'.\n", argv[optind + 1]);
                return EXIT_FAILURE;
            }
            have_size = 1;
        }
    } else {
        char *endptr;
        long pid_long;

        if (npos < 2 || npos > 3) {
            fprintf(stderr, npos < 2 ? "Error: too few arguments.\n"
                                     : "Error: too many arguments.\n");
            return EXIT_FAILURE;
        }
        errno = 0;
        pid_long = strtol(argv[optind], &endptr, BASE_DECIMAL);
        if (errno != 0 || *endptr != '\0' || argv[optind][0] == '\0' || pid_long <= 0) {
            fprintf(stderr, "Error: Invalid PID.\n");
            return EXIT_FAILURE;
        }
        if ((unsigned long)pid_long > get_system_pid_max()) {
            fprintf(stderr, "Error: PID out of range.\n");
            return EXIT_FAILURE;
        }
        pid = (unsigned int)pid_long;

        /*
         * The target is a hex address, or a symbol resolved against the process
         * itself. A 0x prefix or an all-hex-digit token is an address; anything
         * with a non-hex character is a symbol name, looked up in the process's
         * own objects. Resolution and its failure live here, in the CLI - the
         * kernel only ever sees a (pid, address) pair.
         */
        {
            const char *tgt = argv[optind + 1];
            const char *h = tgt;
            int is_hex = tgt[0] != '\0';

            if (h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
                h += 2;
            }
            if (*h == '\0') {
                is_hex = 0;
            }
            for (; *h; ++h) {
                if (!isxdigit((unsigned char)*h)) {
                    is_hex = 0;
                    break;
                }
            }

            if (is_hex) {
                if (parse_vaddr(tgt, &start) != 0) {
                    fprintf(stderr, "Error: Invalid Address.\n");
                    return EXIT_FAILURE;
                }
            } else {
                char err[256];

                if (resolve_user_sym(pid, tgt, &start, err, sizeof(err)) != 0) {
                    fprintf(stderr, "Error: %s\n", err);
                    return EXIT_FAILURE;
                }
                fprintf(stderr, "resolved %s in PID %u -> 0x%llx\n", tgt, pid, start);
            }
        }
        if (npos == 3) {
            if (parse_size(argv[optind + 2], &size) != 0) {
                fprintf(stderr, "Error: invalid size '%s'.\n", argv[optind + 2]);
                return EXIT_FAILURE;
            }
            have_size = 1;
        }
    }

    if (size > (256ULL << 20)) {
        fprintf(stderr, "Error: size too large (max 256 MiB per invocation).\n");
        return EXIT_FAILURE;
    }

    fd = open(PAGEWALKER_PATH, O_RDWR);
    if (fd < 0) {
        switch (errno) {
        case EACCES:
            fprintf(stderr, "Error: cannot open %s: Permission denied (run as root, e.g. with sudo).\n",
                    PAGEWALKER_PATH);
            break;
        case ENOENT:
            fprintf(stderr, "Error: %s not found (is the module loaded?).\n",
                    PAGEWALKER_PATH);
            break;
        default:
            perror("Error opening device");
            break;
        }
        goto cleanup;
    }

    /* Legacy path: a process walk with no dump uses command 1 verbatim. */
    if (!kernel && !have_size) {
        struct pagewalker_request req;
        char buf[BUFFER_SIZE];

        memset(&req, 0, sizeof(req));
        req.pid = pid;
        req.info.target_vaddr = start;

        if (ioctl(fd, PAGEWALKER_IOC_GET_INFO, &req) < 0) {
            switch (errno) {
            case ESRCH:
                fprintf(stderr, "Error: PID %u not found.\n", req.pid);
                break;
            case EADDRNOTAVAIL:
                fprintf(stderr, "Error: 0x%llx is not a canonical address.\n", start);
                break;
            case EINVAL:
                fprintf(stderr, "Error: PID %u is out of range.\n", req.pid);
                break;
            default:
                perror("ioctl");
                break;
            }
            goto cleanup;
        }

        build_report(buf, &req.info, req.pid, 0);
        printf("%s", buf);
        ret_code = EXIT_SUCCESS;
        goto cleanup;
    }

    /* Read path (command 2): fills the walk of the start address and the bytes. */
    {
        struct pagewalker_result info;
        unsigned char *data = NULL;
        unsigned long long got = 0;
        unsigned int stopped = PW_STOP_OK;
        int r;

        memset(&info, 0, sizeof(info));
        if (size) {
            data = malloc(size);
            if (!data) {
                fprintf(stderr, "Error: out of memory for %llu bytes.\n", size);
                goto cleanup;
            }
        }

        r = do_read(fd, kernel, allow_mmio, pid, start, size, data, &got, &stopped, &info);
        if (r < 0) {
            switch (-r) {
            case ESRCH:
                fprintf(stderr, "Error: PID %u not found.\n", pid);
                break;
            case EINVAL:
                fprintf(stderr, "Error: PID %u is out of range.\n", pid);
                break;
            case EOPNOTSUPP:
                fprintf(stderr,
                        "Error: kernel-space walk is not supported on this arm64 "
                        "configuration (52-bit PA / LPA2).\n");
                break;
            default:
                errno = -r;
                perror("ioctl");
                break;
            }
            free(data);
            goto cleanup;
        }

        if (fmt == FMT_RAW) {
            if (!force_tty && isatty(STDOUT_FILENO)) {
                fprintf(stderr,
                        "Error: refusing to write raw bytes to a terminal; pipe the output or pass -F.\n");
                free(data);
                goto cleanup;
            }
            if (got && fwrite(data, 1, (size_t)got, stdout) != (size_t)got) {
                perror("write");
                free(data);
                goto cleanup;
            }
            if (stopped != PW_STOP_OK) {
                fprintf(stderr, "Note: stopped after %llu of %llu bytes (%s).\n",
                        got, size, stop_reason(stopped));
            }
        } else {
            char buf[BUFFER_SIZE];

            if (!no_report) {
                build_report(buf, &info, pid, kernel);
                printf("%s", buf);
            }
            if (size) {
                char szs[32];

                human_size(szs, sizeof(szs), info.page_size);
                printf("\n=== Memory Dump: %llu of %llu byte%s ===\n",
                       got, size, size == 1 ? "" : "s");
                printf("  Start VA : 0x%016llx\n", start);
                if (info.is_valid) {
                    printf("  Start PA : 0x%016llx  (%s leaf at %s%s)\n",
                           (unsigned long long)info.final_phys_addr, szs,
                           leaf_level_name(info.mapping_level),
                           info.is_contiguous ? ", contiguous" : "");
                }
                printf("  Offsets below are relative to the start VA.\n");
                if (stopped != PW_STOP_OK) {
                    printf("  (stopped: %s)\n", stop_reason(stopped));
                }
                printf("\n");
                dump_bytes(stdout, data, (size_t)got, fmt == FMT_CJK, cols, group, upper);
            }
        }

        free(data);
        ret_code = EXIT_SUCCESS;
    }

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    /* A truncated or failed write (full pipe, closed reader, disk full) must not
     * be reported as success; fflush surfaces a deferred stdio write error. */
    if (ret_code == EXIT_SUCCESS && fflush(stdout) != 0) {
        perror("write");
        ret_code = EXIT_FAILURE;
    }
    return ret_code;
}
