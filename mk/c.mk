MK_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
MK_PROJECT := $(firstword $(MAKEFILE_LIST))

ifeq ($(origin CC),default)
CC := gcc
endif
SANITIZE ?= address
STD ?= c99
BIN_ROOT ?= bin
BUILD_ROOT ?= build
CTAGS ?= ctags
CSCOPE ?= cscope
CLANG_FORMAT ?= clang-format
CLANG ?= clang
CPPCHECK ?= cppcheck

MAKEFLAGS += --no-builtin-rules
ifeq ($(filter -j%,$(MAKEFLAGS)),)
MAKEFLAGS += -j$(shell nproc 2>/dev/null || echo 1)
endif

.SUFFIXES:
.DELETE_ON_ERROR:
%: %.c
%.o: %.c
%: %.o

MK_STANDARD_GOALS := all debug sanitize release index compdb tags cscope clean-index clean distclean \
	unused format format-check help
MK_GOALS := $(or $(MAKECMDGOALS),all)

ifneq ($(word 2,$(MAKECMDGOALS)),)

MK_SEQUENTIAL := 1

.PHONY: $(MAKECMDGOALS) mk-run-goals

$(MAKECMDGOALS): mk-run-goals
	@:

mk-run-goals:
	@set -e; for goal in $(MAKECMDGOALS); do $(MAKE) --no-print-directory $$goal; done

else

.DEFAULT_GOAL := all
.PHONY: $(MK_STANDARD_GOALS) $(PROGRAMS) FORCE

comma := ,
empty :=
space := $(empty) $(empty)
define newline


endef

MK_INDEX_SRCS := $(or $(INDEX_SRCS),$(shell git ls-files -- '*.c' '*.h' 2> /dev/null))
MK_FORMAT_SRCS := $(or $(FORMAT_SRCS),$(MK_INDEX_SRCS))
MK_INDEX_FILES := compile_commands.json compile_commands.json.tmp tags cscope.files cscope.out \
	cscope.in.out cscope.po.out
MK_TOOL_OUTPUTS := gmon.out perf.data perf.data.old uftrace.data uftrace.data.old core core.[0-9]* \
	vgcore.[0-9]* callgrind.out.[0-9]* cachegrind.out.[0-9]* massif.out.[0-9]* helgrind.out.[0-9]* \
	drd.out.[0-9]*
MK_CACHES := .cache

ifneq ($(filter-out clean clean-index distclean format format-check help tags cscope,$(MK_GOALS)),)

MK_TRIPLE := $(shell $(CC) -dumpmachine 2> /dev/null)
ifeq ($(MK_TRIPLE),)
$(error CC=$(CC) did not answer -dumpmachine; check that it is installed)
endif
ifeq ($(findstring -linux,$(MK_TRIPLE)),)
$(error CC=$(CC) targets $(MK_TRIPLE), but this project builds for Linux only)
endif
MK_ARCH := $(firstword $(subst -, ,$(MK_TRIPLE)))
MK_FAMILY := $(if $(filter 1,$(shell printf '__clang__\n' | $(CC) -E -P -x c - 2> /dev/null)),clang,gcc)
TAG := $(MK_ARCH)-linux-$(MK_FAMILY)
MK_CC_PATH := $(shell command -v $(firstword $(CC)) 2> /dev/null)
MK_PROBE := $(BUILD_ROOT)/probe/$(TAG)-$(shell printf '%s' '$(CC)' | md5sum | cut -c1-8).mk

MK_DEBUG_CFLAGS := -O0 -ggdb3 -fdebug-macro -fno-builtin -fno-inline -fno-omit-frame-pointer \
	-mno-omit-leaf-frame-pointer -fno-optimize-sibling-calls -fasynchronous-unwind-tables \
	-fno-stack-protector -fno-stack-clash-protection -fcf-protection=none -mbranch-protection=none \
	-U_FORTIFY_SOURCE -ffp-contract=off -mno-relax -fno-eliminate-unused-debug-types \
	-fkeep-inline-functions -fkeep-static-functions -fkeep-persistent-storage-variables \
	-grecord-gcc-switches -pg -fno-pie
MK_DEBUG_LDFLAGS := -pg -no-pie -rdynamic -Wl,--build-id
MK_RELEASE_CFLAGS := -O2 -g -fasynchronous-unwind-tables -fstack-protector-strong \
	-fstack-clash-protection -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -Wformat \
	-Werror=format-security -fcf-protection=full -mbranch-protection=standard -U_FORTIFY_SOURCE \
	-D_FORTIFY_SOURCE=3 -DNDEBUG -fPIE
MK_RELEASE_LDFLAGS := -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,pack-relative-relocs \
	-Wl,--as-needed -Wl,--build-id
MK_LTO_gcc := -flto=auto -fno-fat-lto-objects
MK_LTO_clang := -flto=thin
MK_STATIC_DROP_debug := -no-pie -rdynamic
MK_STATIC_DROP_release := -pie

mk_probe_compile = acc=; for flag in $(2); do if $(CC) -Werror $$acc $$flag -x c -c /dev/null \
	-o $(@D)/probe.o > /dev/null 2>&1; then acc="$$acc $$flag"; printf '$(1) += %s\n' "$$flag" >> $@.tmp; \
	else dropped="$$dropped $$flag"; fi; done

mk_probe_link = acc=; for flag in $(2); do if printf 'int main(void) { return 0; }\n' | $(CC) -Werror $(3) $$acc \
	$$flag -x c - -o $(@D)/probe.out -Wl,--fatal-warnings > /dev/null 2>&1; then acc="$$acc $$flag"; \
	printf '$(1) += %s\n' "$$flag" >> $@.tmp; else dropped="$$dropped $$flag"; fi; done

$(MK_PROBE): $(MK_DIR)/c.mk $(MK_CC_PATH)
	@mkdir -p $(@D)
	@if ! $(CC) -Werror -x c -c /dev/null -o $(@D)/probe.o > /dev/null 2>&1; then \
	    echo "CC=$(CC) cannot compile an empty file with -Werror; pass link-only flags such as -fuse-ld in LDFLAGS"; \
	    exit 1; \
	fi
	@printf 'MK_PROBED_CC := %s\n' '$(CC)' > $@.tmp
	@dropped=; \
	$(call mk_probe_compile,MK_DEBUG_CFLAGS_OK,$(MK_DEBUG_CFLAGS)); \
	$(call mk_probe_link,MK_DEBUG_LDFLAGS_OK,$(MK_DEBUG_LDFLAGS),-fno-pie); \
	$(call mk_probe_compile,MK_RELEASE_CFLAGS_OK,$(MK_RELEASE_CFLAGS)); \
	$(call mk_probe_link,MK_RELEASE_LDFLAGS_OK,$(MK_RELEASE_LDFLAGS),-fPIE); \
	if printf 'int main(void) { return 0; }\n' | $(CC) -O2 $(MK_LTO_$(MK_FAMILY)) -x c - \
        -o $(@D)/probe.out > /dev/null 2>&1; then \
        printf 'MK_LTO_OK := %s\n' '$(MK_LTO_$(MK_FAMILY))' >> $@.tmp; \
    else \
        dropped="$$dropped $(MK_LTO_$(MK_FAMILY))"; \
    fi; \
	rm -f $(@D)/probe.o $(@D)/probe.out; \
	echo "$(TAG): probed $(CC)$${dropped:+; dropped:$$dropped}"
	@mv $@.tmp $@

include $(MK_PROBE)

ifneq ($(filter all sanitize,$(MK_GOALS)),)
MK_SANITIZE_OK := $(shell probe=$$(mktemp) || exit 0; printf 'int main(void) { return 0; }\n' | \
	$(CC) -fsanitize=$(SANITIZE) -x c - -o "$$probe" > /dev/null 2>&1 && echo yes; rm -f "$$probe")
endif

MK_COMMON_CFLAGS = -std=$(STD) -Wall -Wextra -pedantic -Wshadow $(WARNINGS_EXTRA) $(CPPFLAGS_EXTRA)
MK_CFLAGS_debug = $(MK_DEBUG_CFLAGS_OK)
MK_LDFLAGS_debug = $(MK_DEBUG_LDFLAGS_OK)
MK_CFLAGS_sanitize = $(MK_DEBUG_CFLAGS_OK) -fsanitize=$(SANITIZE) -fno-sanitize-recover=all
MK_LDFLAGS_sanitize = $(MK_DEBUG_LDFLAGS_OK) -fsanitize=$(SANITIZE)
MK_CFLAGS_release = $(MK_RELEASE_CFLAGS_OK) $(MK_LTO_OK)
MK_LDFLAGS_release = $(MK_RELEASE_LDFLAGS_OK) $(MK_LTO_OK)

mk_srcs = $(or $($(1)_SRCS),$(1).c)
mk_objs = $(addprefix $(BUILD_ROOT)/$(TAG)-$(1)/,$(patsubst %.c,%.o,$(2)))
mk_bin = $(BIN_ROOT)/$(TAG)-$(1)/$(2)
mk_ldflags = $(if $($(2)_STATIC),$(filter-out $(MK_STATIC_DROP_$(1)),$(MK_LDFLAGS_$(1))) -static,$(MK_LDFLAGS_$(1)))

MK_PROGRAMS_debug := $(PROGRAMS)
MK_PROGRAMS_sanitize := $(foreach p,$(PROGRAMS),$(if $($(p)_STATIC),,$(p)))
MK_PROGRAMS_release := $(PROGRAMS)
MK_MODES := debug sanitize release

define mk_mode_rules
$(BUILD_ROOT)/$(TAG)-$(1)/%.o: %.c $(MK_PROJECT) $(MK_DIR)/c.mk $(MK_PROBE)
	@mkdir -p $$(@D)
	$$(CC) $$(MK_COMMON_CFLAGS) $$(MK_CFLAGS_$(1)) -MMD -MP $$(CFLAGS) -c $$< -o $$@
endef

define mk_prog_rules
$(call mk_bin,$(1),$(2)): $(call mk_objs,$(1),$(call mk_srcs,$(2)) $(LIB_SRCS))
	@mkdir -p $$(@D)
	$$(CC) $$(MK_CFLAGS_$(1)) $$(CFLAGS) $$^ -o $$@ $$(call mk_ldflags,$(1),$(2)) $$(LDFLAGS_EXTRA) \
		$$(LDFLAGS) $$(LDLIBS)
endef

$(foreach m,$(MK_MODES),$(eval $(call mk_mode_rules,$(m))))
$(foreach m,$(MK_MODES),$(foreach p,$(MK_PROGRAMS_$(m)),$(eval $(call mk_prog_rules,$(m),$(p)))))
$(foreach p,$(PROGRAMS),$(eval $(p): $(call mk_bin,debug,$(p))))

MK_ALL_OBJS := $(sort $(foreach m,$(MK_MODES),$(call mk_objs,$(m),$(LIB_SRCS)) \
	$(foreach p,$(MK_PROGRAMS_$(m)),$(call mk_objs,$(m),$(call mk_srcs,$(p))))))
-include $(MK_ALL_OBJS:.o=.d)

all: debug sanitize $(EXTRA_ALL)

debug: $(foreach p,$(MK_PROGRAMS_debug),$(call mk_bin,debug,$(p))) $(EXTRA_DEBUG)
	@echo "debug programs are in $(BIN_ROOT)/$(TAG)-debug/"

ifeq ($(MK_SANITIZE_OK),yes)
sanitize: $(foreach p,$(MK_PROGRAMS_sanitize),$(call mk_bin,sanitize,$(p)))
	@echo "sanitize ($(SANITIZE)) programs are in $(BIN_ROOT)/$(TAG)-sanitize/"
else
sanitize:
	@echo "skipped sanitize: $(CC) cannot link -fsanitize=$(SANITIZE)"
endif

release: $(foreach p,$(MK_PROGRAMS_release),$(call mk_bin,release,$(p))) $(EXTRA_RELEASE)
	@echo "release programs are in $(BIN_ROOT)/$(TAG)-release/"

MK_COMPDB_SRCS := $(sort $(LIB_SRCS) $(foreach p,$(PROGRAMS),$(call mk_srcs,$(p))))
mk_json_list = $(subst $(space),$(comma)$(space),$(strip $(foreach a,$(1),"$(a)")))
mk_compdb_entry = {"directory": "$(CURDIR)", "file": "$(CURDIR)/$(1)", "arguments": [$(call mk_json_list,$(CC) \
	$(MK_COMMON_CFLAGS) $(MK_CFLAGS_debug) $(CFLAGS) -c $(1) -o $(call mk_objs,debug,$(1)))]}

compdb: compile_commands.json $(EXTRA_COMPDB)

compile_commands.json: $(MK_PROBE) FORCE
	@$(file >$@.tmp,[$(newline)$(subst }$(space){,}$(comma)$(newline){,$(foreach s,$(MK_COMPDB_SRCS),$(call mk_compdb_entry,$(s))))$(newline)])
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; echo "$@ unchanged"; else mv $@.tmp $@; echo "wrote $@"; fi

FORCE:

unused:
	@if command -v $(CLANG) > /dev/null 2>&1; then \
	    for s in $(MK_COMPDB_SRCS); do \
	        $(CLANG) -fsyntax-only $(MK_COMMON_CFLAGS) -Wno-everything -Wunused -Wunused-parameter \
	            -Wunused-macros $$s; \
	    done; \
	else \
	    echo "$(CLANG) not found, skipped the per-file check"; \
	fi
	@if command -v $(CPPCHECK) > /dev/null 2>&1; then \
	    $(CPPCHECK) --enable=unusedFunction --quiet $(CPPFLAGS_EXTRA) \
	        --template='{file}:{line}:{column}: {severity}: {message} [{id}]' $(MK_COMPDB_SRCS) 2>&1 | \
	        grep '\[unusedFunction\]' || true; \
	else \
	    echo "$(CPPCHECK) not found, skipped the cross-file check"; \
	fi

endif

index: compdb tags cscope

tags:
	@if command -v $(CTAGS) > /dev/null 2>&1; then \
	    $(CTAGS) -f tags $(MK_INDEX_SRCS) $(EXTRA_INDEX_SRCS) && echo "wrote tags"; \
	else \
	    echo "$(CTAGS) not found, skipped tags"; \
	fi

cscope:
	@if command -v $(CSCOPE) > /dev/null 2>&1; then \
	    printf '%s\n' $(MK_INDEX_SRCS) $(EXTRA_INDEX_SRCS) > cscope.files && \
	    $(CSCOPE) -bkqu -i cscope.files && echo "wrote cscope.out"; \
	else \
	    echo "$(CSCOPE) not found, skipped cscope.out"; \
	fi

clean-index: $(EXTRA_CLEAN_INDEX)
	rm -f $(MK_INDEX_FILES)

clean: $(EXTRA_CLEAN)
	rm -rf $(BIN_ROOT) $(BUILD_ROOT)

distclean: clean clean-index $(EXTRA_DISTCLEAN)
	rm -rf $(MK_TOOL_OUTPUTS) $(MK_CACHES)

format:
	$(CLANG_FORMAT) -i $(MK_FORMAT_SRCS)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(MK_FORMAT_SRCS)

help:
	@printf '%s\n' \
	    'make, make all    debug and sanitize builds' \
	    'make debug        debug build: -O0, full debug info, -pg, no injected hardening' \
	    'make sanitize     debug build with -fsanitize=$$SANITIZE (default address)' \
	    'make release      optimized, hardened build with LTO' \
	    'make index        compile_commands.json, tags and cscope (also compdb, tags, cscope)' \
	    'make clean-index  remove the index files' \
	    'make clean        remove every build product' \
	    'make distclean    clean, clean-index, tool outputs and caches' \
	    'make unused       unused diagnostics of every source (clang) and unused functions (cppcheck)' \
	    'make format       clang-format the sources (format-check only reports)' \
	    'variables: CC=gcc|clang|<cross compiler>, SANITIZE=address|undefined|thread|...' \
	    $(if $(PROGRAMS),'programs: $(PROGRAMS)')

endif
