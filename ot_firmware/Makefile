# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Generate a baremetal application

# Name of the program $(PROGRAM).c will be added as a source file
PROGRAM = ot_firmware_bck
PROGRAM_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
# Any extra source files to include in the build. Use the upper case .S
# extension for assembly files

OPENTITAN_ROOT := $(abspath $(PROGRAM_DIR)/../../../..)

utils_dir = $(PROGRAM_DIR)/inc/
directories = drivers/inc drivers/src string_lib/inc string_lib/src 
#EXTRA_SRCS = $(foreach d, $(directories), -I$(utils_dir)$d)

INCS += -I$(OPENTITAN_ROOT)

EXTRA_SRCS += \
  $(OPENTITAN_ROOT)/hw/top_earlgrey/sw/autogen/top_earlgrey.c \
  $(OPENTITAN_ROOT)/sw/device/lib/arch/device_sim_verilator.c \
  $(OPENTITAN_ROOT)/sw/device/lib/base/mmio.c \
  $(OPENTITAN_ROOT)/sw/device/lib/base/math.c \
  $(OPENTITAN_ROOT)/sw/device/lib/base/bitfield.c \
  $(OPENTITAN_ROOT)/sw/device/lib/base/memory.c \
  $(OPENTITAN_ROOT)/sw/device/lib/base/math_builtins.c \
  $(OPENTITAN_ROOT)/sw/device/lib/base/status.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/dif_base.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/dif_hmac.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/autogen/dif_hmac_autogen.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/dif_uart.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/dif_aes.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/dif_edn.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/dif_csrng.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/dif_csrng_shared.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/autogen/dif_uart_autogen.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/autogen/dif_aes_autogen.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/autogen/dif_edn_autogen.c \
  $(OPENTITAN_ROOT)/sw/device/lib/dif/autogen/dif_csrng_autogen.c \
  $(OPENTITAN_ROOT)/sw/device/lib/runtime/ibex.c \
  $(OPENTITAN_ROOT)/sw/device/lib/runtime/print.c \
  $(OPENTITAN_ROOT)/sw/device/lib/runtime/hart.c \
  $(OPENTITAN_ROOT)/sw/device/lib/runtime/log.c \
  $(OPENTITAN_ROOT)/sw/device/lib/testing/aes_testutils.c  \
  $(OPENTITAN_ROOT)/sw/device/lib/testing/hmac_testutils.c \
  $(OPENTITAN_ROOT)/sw/device/lib/testing/test_framework/status.c \
  $(OPENTITAN_ROOT)/sw/device/silicon_creator/rom/uart.c \
  $(OPENTITAN_ROOT)/sw/device/silicon_creator/rom/string_lib.c \
  $(OPENTITAN_ROOT)/sw/device/lib/base/abs_mmio.c
  
  
  #$(OPENTITAN_ROOT)/sw/device/lib/testing/test_framework/ottf_main.c 
  #$(OPENTITAN_ROOT)/sw/device/lib/base/math_bm.c 
  #$(OPENTITAN_ROOT)/sw/device/lib/runtime/log.c 
  #$(OPENTITAN_ROOT)/sw/device/lib/testing/status.c 




include ${PROGRAM_DIR}/../common/common.mk

