# SPDX-License-Identifier: 0BSD
ccflags-$(CONFIG_DYNAMIC_DEBUG_CORE) += -DDYNAMIC_DEBUG_MODULE

ifeq ($(PROFILE),debug)
ccflags-y += -DDEBUG -g3 $(call cc-option,-fdebug-macro) $(call cc-option,-fno-eliminate-unused-debug-types) \
	$(call cc-option,-grecord-gcc-switches) -fno-inline -fno-optimize-sibling-calls -fno-builtin \
	-fno-omit-frame-pointer $(call cc-option,-mno-omit-leaf-frame-pointer)
ccflags-remove-y += -fno-var-tracking -femit-struct-debug-baseonly -ftrivial-auto-var-init=zero
ccflags-y += $(call cc-option,-ftrivial-auto-var-init=pattern)
ccflags-$(CONFIG_STACKPROTECTOR) += -fstack-protector-all
KASAN_SANITIZE := y
KCSAN_SANITIZE := y
KMSAN_SANITIZE := y
UBSAN_SANITIZE := y
GCOV_PROFILE := y
KCOV_INSTRUMENT := y
else ifndef CONFIG_DEBUG_INFO
ccflags-y += -g
endif
