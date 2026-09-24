# SPDX-FileCopyrightText: 2026 ETH Zurich and University of Bologna
# SPDX-License-Identifier: Apache-2.0

"""Mailbox-1 asynchronous transport for OpenTitan double buffering.

See docs/OpenTitanDoubleBuffering.md for the required firmware ABI.
"""

from Deeploy.DeeployTypes import NodeTemplate, _ReferenceBuffer
from Deeploy.Targets.PULPOpen.DMA.MchanDma import MchanDma, calcola_sha256
from Deeploy.TilingExtension.AsyncDma import Future, PerTensorWaitingStrategy


class OpenTitanFuture(Future):
    # Completion words live until all transfers have drained at loop teardown.
    _initTemplate = NodeTemplate("""
#ifndef DEEPLOY_OT_ASYNC_ABI
#error "Double buffering requires the OpenTitan asynchronous mailbox ABI"
#elif DEEPLOY_OT_ASYNC_ABI != 1
#error "Unsupported OpenTitan asynchronous mailbox ABI"
#endif
    uint32_t ${name}_submitted = 0;
    volatile uint32_t ${name}_completed = 0;
""")
    _allocTemplate = NodeTemplate("")
    _deinitTemplate = NodeTemplate("")
    _waitTemplate = NodeTemplate("""
    while (${name}_completed != ${name}_submitted) { }
    __asm__ volatile ("fence iorw, iorw" ::: "memory");
""")


class OpenTitanAsyncDma(MchanDma):
    # ACK is admission, not completion. The receiver MUST copy the complete
    # descriptor before clearing SND_STAT. It can then work independently.
    _begin = """
    while (mb_read(MBOX_CAR_INT_SND_STAT(1)) != 0) { }
    __asm__ volatile ("fence iorw, iorw" ::: "memory");
    cl_task.transfer_id = 0x${sha256};
    cl_task.size = ${size};
    cl_task.src = ${loc};
    cl_task.dst = ${ext};
"""
    _end = """
    cl_task.src_key = (uint32_t)(uintptr_t)${external_base};
    cl_task.dst_key = (uint32_t)(uintptr_t)${external_base};
    cl_task.completion_addr = (uint32_t)(uintptr_t)&${future}_completed;
    cl_task.completion_value = ++${future}_submitted;
    __asm__ volatile ("fence iorw, iorw" ::: "memory");
    mailbox_send(1, &cl_task, ${ot_flags});
    mb_write(0x1, MBOX_CAR_INT_SND_SET(1));
    __asm__ volatile ("fence iorw, iorw" ::: "memory");
    while (mb_read(MBOX_CAR_INT_SND_STAT(1)) != 0) { }
    __asm__ volatile ("fence iorw, iorw" ::: "memory");
"""
    _transferTemplates = {
        1: NodeTemplate(_begin + """
    cl_task.src_stride = 0;
    cl_task.dst_stride = 0;
    cl_task.repetitions = 1;
    cl_task.size_1d = ${size};
""" + _end),
        2: NodeTemplate(_begin + """
    cl_task.src_stride = ${stride_src};
    cl_task.dst_stride = ${stride_dst};
    cl_task.repetitions = ${repetitions};
    cl_task.size_1d = ${size_1d};
""" + _end),
    }

    def __init__(self):
        super().__init__(self._transferTemplates)
        # Distinct futures are essential: waiting for input B must not drain
        # the prefetch of input A for the NEXT tile.
        self._waitingStrategy = PerTensorWaitingStrategy(OpenTitanFuture)

    def transferOpRepr(self, ctxt, externalBuffer, localBuffer, shape, strideExt, strideLoc, direction, future):
        op = super().transferOpRepr(ctxt, externalBuffer, localBuffer, shape, strideExt, strideLoc, direction, future)
        # Crypto identity must not change with the ping/pong slot or the C
        # expression used by the prologue versus the steady-state loop.
        root = externalBuffer
        while isinstance(root, _ReferenceBuffer):
            root = ctxt.lookup(root._referenceName)
        op["sha256"] = calcola_sha256(root.name)[:8]
        return op
