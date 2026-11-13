MK_FILE := $(lastword $(MAKEFILE_LIST))
MK_PROJECT := $(firstword $(MAKEFILE_LIST))

ifeq ($(origin CC),default)
CC := gcc
endif
PROFILE ?= debug
SANITIZE ?= address
STD ?= c99
BIN_DIR ?= bin
BUILD_DIR ?= build
CTAGS ?= ctags
CSCOPE ?= cscope
CLANG_FORMAT ?= clang-format
CLANG ?= clang
CPPCHECK ?= cppcheck

ifneq ($(words $(filter debug release,$(PROFILE))) $(words $(PROFILE)),1 1)
$(error PROFILE takes debug or release, not '$(PROFILE)')
endif

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
	unused format format-check list help
MK_GOALS := $(or $(MAKECMDGOALS),all)
MK_ALL_debug := debug sanitize
MK_ALL_release := release

ifneq ($(word 2,$(MAKECMDGOALS)),)

MK_SEQUENTIAL := 1

.PHONY: $(MAKECMDGOALS) run-goals-in-order

$(MAKECMDGOALS): run-goals-in-order
	@:

run-goals-in-order:
	@set -e; for goal in $(MAKECMDGOALS); do $(MAKE) --no-print-directory $$goal; done

else

.DEFAULT_GOAL := all
.PHONY: $(MK_STANDARD_GOALS) $(PROGRAMS) FORCE

comma := ,
empty :=
space := $(empty) $(empty)
define newline


endef

mk_count = $(words $(1)) $(if $(filter 1,$(words $(1))),$(2),$(3))
MK_HELP_LIST := 10
MK_HELP_MORE = $(wordlist 11,$(words $(PROGRAMS)),$(PROGRAMS))

MK_INDEX_SRCS := $(or $(INDEX_SRCS),$(shell git ls-files -- '*.c' '*.h' 2> /dev/null),$(patsubst ./%,%,$(shell \
	find . \( -path './.*' -o -path './$(BIN_DIR)' -o -path './$(BUILD_DIR)' \) -prune -o \
	\( -name '*.[ch]' ! -name '*.mod.c' \) -print 2> /dev/null | sort)))
MK_FORMAT_SRCS := $(or $(FORMAT_SRCS),$(MK_INDEX_SRCS))
MK_INDEX_FILES := compile_commands.json compile_commands.json.tmp tags cscope.files cscope.out \
	cscope.in.out cscope.po.out
MK_TOOL_OUTPUTS := gmon.out perf.data perf.data.old uftrace.data uftrace.data.old core core.[0-9]* \
	vgcore.[0-9]* callgrind.out.[0-9]* cachegrind.out.[0-9]* massif.out.[0-9]* helgrind.out.[0-9]* \
	drd.out.[0-9]*
MK_CACHES := .cache

ifneq ($(filter-out clean clean-index distclean format format-check list help tags cscope,$(MK_GOALS)),)

MK_TRIPLE := $(shell $(CC) -dumpmachine 2> /dev/null)
ifeq ($(MK_TRIPLE),)
$(error CC=$(CC) did not answer -dumpmachine; check that it is installed)
endif
ifeq ($(findstring -linux,$(MK_TRIPLE)),)
$(error CC=$(CC) targets $(MK_TRIPLE), but this project builds for Linux only)
endif
MK_ARCH := $(firstword $(subst -, ,$(MK_TRIPLE)))
MK_FAMILY := $(if $(filter 1,$(shell printf '__clang__\n' | $(CC) -E -P -x c - 2> /dev/null)),clang,gcc)
MK_TARGET := $(MK_ARCH)-linux-$(MK_FAMILY)
MK_CC_PATH := $(shell command -v $(firstword $(CC)) 2> /dev/null)
MK_PROBE := $(BUILD_DIR)/probe/$(MK_TARGET)-$(shell printf '%s' '$(CC)' | md5sum | cut -c1-8).mk

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

mk_probe_compile = acc=; drop=; for flag in $(3); do if $(CC) -Werror $$acc $$flag -x c -c /dev/null \
	-o $(@D)/probe.o > /dev/null 2>&1; then acc="$$acc $$flag"; printf '$(1) += %s\n' "$$flag" >> $@.tmp; \
	else drop="$$drop $$flag"; fi; done; echo "=> $(2):$$acc"; [ -z "$$drop" ] || echo "=> $(2) dropped:$$drop"

mk_probe_link = acc=; drop=; for flag in $(3); do if printf 'int main(void) { return 0; }\n' | $(CC) -Werror $(4) \
	$$acc $$flag -x c - -o $(@D)/probe.out -Wl,--fatal-warnings > /dev/null 2>&1; then acc="$$acc $$flag"; \
	printf '$(1) += %s\n' "$$flag" >> $@.tmp; else drop="$$drop $$flag"; fi; done; echo "=> $(2):$$acc"; \
	[ -z "$$drop" ] || echo "=> $(2) dropped:$$drop"

$(MK_PROBE): $(MK_FILE) $(MK_CC_PATH)
	@mkdir -p $(@D)
	@if ! $(CC) -Werror -x c -c /dev/null -o $(@D)/probe.o > /dev/null 2>&1; then \
	    echo "CC=$(CC) cannot compile an empty file with -Werror; pass link-only flags such as -fuse-ld in LDFLAGS"; \
	    exit 1; \
	fi
	@printf 'MK_PROBED_CC := %s\n' '$(CC)' > $@.tmp
	@echo "=> target: $(MK_TARGET), $(CC) $$($(CC) -dumpfullversion 2> /dev/null || $(CC) -dumpversion)"; \
	echo "=> common flags: $(strip $(MK_COMMON_CFLAGS))"; \
	$(call mk_probe_compile,MK_DEBUG_CFLAGS_OK,debug,$(MK_DEBUG_CFLAGS)); \
	$(call mk_probe_link,MK_DEBUG_LDFLAGS_OK,debug link,$(MK_DEBUG_LDFLAGS),-fno-pie); \
	$(call mk_probe_compile,MK_RELEASE_CFLAGS_OK,release,$(MK_RELEASE_CFLAGS)); \
	$(call mk_probe_link,MK_RELEASE_LDFLAGS_OK,release link,$(MK_RELEASE_LDFLAGS),-fPIE); \
	if printf 'int main(void) { return 0; }\n' | $(CC) -O2 $(MK_LTO_$(MK_FAMILY)) -x c - \
	    -o $(@D)/probe.out > /dev/null 2>&1; then \
	    printf 'MK_LTO_OK := %s\n' '$(MK_LTO_$(MK_FAMILY))' >> $@.tmp; \
	    echo "=> release link-time optimization (LTO): $(MK_LTO_$(MK_FAMILY))"; \
	else \
	    echo "=> release link-time optimization (LTO) dropped: $(MK_LTO_$(MK_FAMILY))"; \
	fi; \
	rm -f $(@D)/probe.o $(@D)/probe.out
	@mv $@.tmp $@

include $(MK_PROBE)

ifneq ($(filter sanitize,$(patsubst all,$(MK_ALL_$(PROFILE)),$(MK_GOALS))),)
MK_SANITIZE_OK := $(shell probe=$$(mktemp) || exit 0; printf 'int main(void) { return 0; }\n' | \
	$(CC) -fsanitize=$(SANITIZE) -x c - -o "$$probe" > /dev/null 2>&1 && echo yes; rm -f "$$probe")
endif

MK_COMMON_CFLAGS = -std=$(STD) -Wall -Wextra -pedantic -Wshadow $(WARNINGS_EXTRA) $(CFLAGS_EXTRA) \
	$(CPPFLAGS_EXTRA)
MK_CFLAGS_debug = $(MK_DEBUG_CFLAGS_OK)
MK_LDFLAGS_debug = $(MK_DEBUG_LDFLAGS_OK)
MK_CFLAGS_sanitize = $(MK_DEBUG_CFLAGS_OK) -fsanitize=$(SANITIZE) -fno-sanitize-recover=all
MK_LDFLAGS_sanitize = $(MK_DEBUG_LDFLAGS_OK) -fsanitize=$(SANITIZE)
MK_CFLAGS_release = $(MK_RELEASE_CFLAGS_OK) $(MK_LTO_OK)
MK_LDFLAGS_release = $(MK_RELEASE_LDFLAGS_OK) $(MK_LTO_OK)

mk_srcs = $(or $($(1)_SRCS),$(1).c)
mk_objs = $(addprefix $(BUILD_DIR)/$(MK_TARGET)-$(1)/,$(patsubst %.c,%.o,$(2)))
mk_bin = $(BIN_DIR)/$(MK_TARGET)-$(1)/$(2)
mk_ldflags = $(if $($(2)_STATIC),$(filter-out $(MK_STATIC_DROP_$(1)),$(MK_LDFLAGS_$(1))) -static,$(MK_LDFLAGS_$(1)))

MK_PROGRAMS_debug := $(PROGRAMS)
MK_PROGRAMS_sanitize := $(foreach p,$(PROGRAMS),$(if $($(p)_STATIC),,$(p)))
MK_PROGRAMS_release := $(PROGRAMS)
MK_PROGRAMS_static := $(strip $(foreach p,$(PROGRAMS),$(if $($(p)_STATIC),$(p))))
MK_MODES := debug sanitize release

define mk_mode_rules
$(BUILD_DIR)/$(MK_TARGET)-$(1)/%.o: %.c $(MK_PROJECT) $(MK_FILE) $(MK_PROBE)
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
$(foreach p,$(PROGRAMS),$(eval $(p): $(call mk_bin,$(PROFILE),$(p))))

MK_ALL_OBJS := $(sort $(foreach m,$(MK_MODES),$(call mk_objs,$(m),$(LIB_SRCS)) \
	$(foreach p,$(MK_PROGRAMS_$(m)),$(call mk_objs,$(m),$(call mk_srcs,$(p))))))
-include $(MK_ALL_OBJS:.o=.d)

all: $(MK_ALL_$(PROFILE)) $(EXTRA_ALL)
	@$(mk_refresh_compdb)

debug: $(foreach p,$(MK_PROGRAMS_debug),$(call mk_bin,debug,$(p))) $(EXTRA_DEBUG)
	@echo "=> debug: $(call mk_count,$(MK_PROGRAMS_debug),program,programs) in $(BIN_DIR)/$(MK_TARGET)-debug/"
	@$(if $(filter debug,$(MK_GOALS)),$(mk_refresh_compdb))

ifeq ($(MK_SANITIZE_OK),yes)
sanitize: $(foreach p,$(MK_PROGRAMS_sanitize),$(call mk_bin,sanitize,$(p)))
	@echo "=> sanitize ($(SANITIZE)): $(call mk_count,$(MK_PROGRAMS_sanitize),program,programs) in\
	 $(BIN_DIR)/$(MK_TARGET)-sanitize/$(if $(MK_PROGRAMS_static),; static$(comma) so not sanitized: $(MK_PROGRAMS_static))"
	@$(if $(filter sanitize,$(MK_GOALS)),$(mk_refresh_compdb))
else
sanitize:
	@echo "=> sanitize ($(SANITIZE)): skipped, $(CC) cannot link -fsanitize=$(SANITIZE)"
endif

release: $(foreach p,$(MK_PROGRAMS_release),$(call mk_bin,release,$(p))) $(EXTRA_RELEASE)
	@echo "=> release: $(call mk_count,$(MK_PROGRAMS_release),program,programs) in $(BIN_DIR)/$(MK_TARGET)-release/"
	@$(if $(filter release,$(MK_GOALS)),$(mk_refresh_compdb))

MK_COMPDB_SRCS := $(sort $(LIB_SRCS) $(foreach p,$(PROGRAMS),$(call mk_srcs,$(p))))
mk_json_list = $(subst $(space),$(comma)$(space),$(strip $(foreach a,$(1),"$(a)")))
mk_compdb_entry = {"directory": "$(CURDIR)", "file": "$(CURDIR)/$(1)", "arguments": [$(call mk_json_list,$(CC) \
	$(MK_COMMON_CFLAGS) $(MK_CFLAGS_$(PROFILE)) $(CFLAGS) -c $(1) -o $(call mk_objs,$(PROFILE),$(1)))]}

compdb: compile_commands.json $(EXTRA_COMPDB)

define mk_write_compdb
$(file >compile_commands.json.tmp,[$(newline)$(subst }$(space){,}$(comma)$(newline){,$(foreach s,$(MK_COMPDB_SRCS),$(call mk_compdb_entry,$(s))))$(newline)])
endef

mk_compdb_state = if cmp -s compile_commands.json.tmp compile_commands.json; then rm -f compile_commands.json.tmp; \
	state=unchanged; else mv compile_commands.json.tmp compile_commands.json; state=written; fi
mk_compdb_report = echo "=> compile_commands.json: $(call mk_count,$(MK_COMPDB_SRCS),entry,entries) with the $(PROFILE) flags, $$state"
mk_refresh_compdb = $(if $(wildcard compile_commands.json),$(mk_write_compdb)$(mk_compdb_state); \
	[ $$state = unchanged ] || $(mk_compdb_report),:)

compile_commands.json: $(MK_PROBE) FORCE
	@$(mk_write_compdb)
	@$(mk_compdb_state); $(mk_compdb_report)

FORCE:

MK_UNUSED_DEFS = $(filter -D% -U%,$(MK_CFLAGS_$(PROFILE)))

unused:
	@if command -v $(CLANG) > /dev/null 2>&1; then \
	    echo "=> unused (clang): -Wunused -Wunused-parameter -Wunused-macros over\
	 $(call mk_count,$(MK_COMPDB_SRCS),source,sources) with the $(PROFILE) definitions"; \
	    for s in $(MK_COMPDB_SRCS); do \
	        $(CLANG) -fsyntax-only $(MK_COMMON_CFLAGS) $(MK_UNUSED_DEFS) -Wno-everything -Wunused \
	            -Wunused-parameter -Wunused-macros $$s; \
	    done; \
	else \
	    echo "=> unused (clang): skipped, $(CLANG) not found"; \
	fi
	@if command -v $(CPPCHECK) > /dev/null 2>&1; then \
	    echo "=> unused (cppcheck): unusedFunction over $(call mk_count,$(MK_COMPDB_SRCS),source,sources)"; \
	    $(CPPCHECK) --enable=unusedFunction --quiet $(CPPFLAGS_EXTRA) $(MK_UNUSED_DEFS) \
	        --template='{file}:{line}:{column}: {severity}: {message} [{id}]' $(MK_COMPDB_SRCS) 2>&1 | \
	        grep '\[unusedFunction\]' || true; \
	else \
	    echo "=> unused (cppcheck): skipped, $(CPPCHECK) not found"; \
	fi

endif

index: compdb tags cscope

tags:
	@if command -v $(CTAGS) > /dev/null 2>&1; then \
	    $(CTAGS) -f tags $(MK_INDEX_SRCS) $(EXTRA_INDEX_SRCS) && \
	    echo "=> tags: $(call mk_count,$(MK_INDEX_SRCS) $(EXTRA_INDEX_SRCS),file,files)"; \
	else \
	    echo "=> tags: skipped, $(CTAGS) not found"; \
	fi

cscope:
	@if command -v $(CSCOPE) > /dev/null 2>&1; then \
	    printf '%s\n' $(MK_INDEX_SRCS) $(EXTRA_INDEX_SRCS) > cscope.files && \
	    $(CSCOPE) -bkqu -i cscope.files && \
	    echo "=> cscope.out: $(call mk_count,$(MK_INDEX_SRCS) $(EXTRA_INDEX_SRCS),file,files)"; \
	else \
	    echo "=> cscope.out: skipped, $(CSCOPE) not found"; \
	fi

clean-index: $(EXTRA_CLEAN_INDEX)
	@rm -f $(MK_INDEX_FILES)
	@echo "=> clean-index: removed compile_commands.json, tags and cscope.*"

clean: $(EXTRA_CLEAN)
	@rm -rf $(BIN_DIR) $(BUILD_DIR)
	@echo "=> clean: removed $(BIN_DIR)/ and $(BUILD_DIR)/"

distclean: clean clean-index $(EXTRA_DISTCLEAN)
	@rm -rf $(MK_TOOL_OUTPUTS) $(MK_CACHES)
	@echo "=> distclean: removed tool outputs (gmon.out, perf.data, uftrace.data, core, valgrind) and $(MK_CACHES)/"

format:
	@$(CLANG_FORMAT) -i $(MK_FORMAT_SRCS)
	@echo "=> format: $(call mk_count,$(MK_FORMAT_SRCS),file,files) formatted in place"

format-check:
	@$(CLANG_FORMAT) --dry-run --Werror $(MK_FORMAT_SRCS)
	@echo "=> format-check: $(call mk_count,$(MK_FORMAT_SRCS),file,files) already formatted"

help:
	@printf '%s\n' \
	    'usage: make [goal ...] [VARIABLE=value ...]' \
	    '' \
	    'goals:' \
	    '  all           the debug and sanitize builds, or the release build with PROFILE=release' \
	    '  debug         -O0, full debug info, -pg, no default hardening, no PIE' \
	    '  sanitize      the debug flags plus -fsanitize=SANITIZE' \
	    '  release       -O2, hardened, PIE, link-time optimization (LTO)' \
	    '  index         compile_commands.json with the PROFILE flags, tags and cscope.out' \
	    '  compdb        compile_commands.json only (tags and cscope make the other two)' \
	    '  clean-index   remove compile_commands.json, tags and cscope.*' \
	    '  clean         remove bin/ and build/' \
	    '  distclean     clean, clean-index, tool outputs and .cache/' \
	    '  unused        unused diagnostics of every source (clang) and unused functions (cppcheck)' \
	    '  format        clang-format every source in place (format-check only lists the changes)' \
	    '  list          print every program' \
	    $(EXTRA_HELP_GOALS) \
	    '  help          print this help' \
	    '' \
	    'variables:' \
	    '  PROFILE=debug|release  what all builds and which flags index and unused use (default debug)' \
	    '  SANITIZE=<list>        sanitizers of the sanitize build, comma separated (default address)' \
	    '  CC=<compiler>          gcc (default), clang or a cross compiler such as aarch64-linux-gnu-gcc' \
	    $(EXTRA_HELP_VARIABLES) \
	    '' \
	    'Each mode builds into bin/<target>-<mode>/ and build/<target>-<mode>/, where <target> is' \
	    '<arch>-linux-<cc>, for example bin/x86_64-linux-gcc-debug/. Goals run in the order given.' \
	    $(if $(PROGRAMS),'' 'programs ($(words $(PROGRAMS))):' $(foreach p,$(wordlist 1,$(MK_HELP_LIST),$(PROGRAMS)),'  $(p)') \
	    $(if $(MK_HELP_MORE),'  ... $(words $(MK_HELP_MORE)) more; make list prints every program'))

list:
	@printf '%s\n' $(PROGRAMS)

endif
