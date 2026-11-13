# SPDX-License-Identifier: 0BSD
ccflags-$(CONFIG_DYNAMIC_DEBUG_CORE) += -DDYNAMIC_DEBUG_MODULE

ifeq ($(PROFILE),debug)
ccflags-y += -DDEBUG -g3 $(call cc-option,-fdebug-macro) -fno-optimize-sibling-calls \
	$(call cc-option,-fno-inline-functions-called-once)
ccflags-remove-y += -fno-var-tracking -femit-struct-debug-baseonly
ccflags-$(CONFIG_STACKPROTECTOR) += -fstack-protector-all
ccflags-remove-$(CONFIG_INIT_STACK_ALL_ZERO) += -ftrivial-auto-var-init=zero
ccflags-$(CONFIG_INIT_STACK_ALL_ZERO) += -ftrivial-auto-var-init=pattern
GCOV_PROFILE := y
KCOV_INSTRUMENT := y
else ifndef CONFIG_DEBUG_INFO
ccflags-y += -g
endif
