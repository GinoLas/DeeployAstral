# SPDX-FileCopyrightText: 2026 ETH Zurich and University of Bologna
# SPDX-License-Identifier: Apache-2.0

"""Host-only regression tests for the OpenTitan asynchronous code generator."""
import unittest
from itertools import product

from Deeploy.AbstractDataTypes import PointerClass
from Deeploy.CommonExtensions.DataTypes import int8_t
from Deeploy.DeeployTypes import (CodeSnippet, ConstantBuffer, ExecutionBlock, NetworkContext,
                                 NodeTemplate, StructBuffer, TransientBuffer, VariableBuffer)
from Deeploy.Targets.PULPOpen.CodeTransformationPasses.PULPClusterTiling import PULPClusterTiling
from Deeploy.Targets.PULPOpen.DMA.MchanDma import MchanDma
from Deeploy.Targets.PULPOpen.DMA.OpenTitanAsyncDma import OpenTitanAsyncDma
from Deeploy.TilingExtension.AsyncDma import AnydimAsyncDmaTransferAdapter
from Deeploy.TilingExtension.MemoryConstraints import MemoryConstraint, NodeMemoryConstraint, TensorMemoryConstraint
from Deeploy.TilingExtension.TilingCodegen import HyperRectangle, TilingSchedule, VariableReplacementScheme


def context():
    return NetworkContext(VariableBuffer, ConstantBuffer, StructBuffer, TransientBuffer)


def tensor(ctxt, name, shape, constant=False):
    buff = ConstantBuffer(name, shape, [0]) if constant else VariableBuffer(name, shape)
    buff._type = PointerClass(int8_t)
    buff._memoryLevel = 'L2'
    buff.id = len(ctxt.globalObjects)
    ctxt.add(buff, 'global')
    return buff


def render(snippets):
    return '\n'.join(s.template.generate(s.operatorRepresentation) for s in snippets)


class OpenTitanCodegenTest(unittest.TestCase):
    def test_selection_and_independent_futures(self):
        legacy = MchanDma()
        passes = PULPClusterTiling('L2', 'L1', legacy)
        self.assertIs(passes.SB.dma, legacy)
        self.assertIs(passes.profilingSB.dma, legacy)
        self.assertIsInstance(passes.DB.dma, OpenTitanAsyncDma)
        self.assertIs(passes.DB.dma, passes.profilingDB.dma)
        dma = passes.DB.dma
        a = dma.getFuture('a', 'ExternalToLocal')
        self.assertIs(a, dma.getFuture('a', 'ExternalToLocal'))
        self.assertIsNot(a, dma.getFuture('b', 'ExternalToLocal'))
        self.assertIsNot(a, dma.getFuture('a', 'LocalToExternal'))
        self.assertIsNot(a, OpenTitanAsyncDma().getFuture('a', 'ExternalToLocal'))
        self.assertNotIn('wait_for_idma_transfer', render([a.wait()]))
        self.assertIn('a_ExternalToLocal_completed != a_ExternalToLocal_submitted', render([a.wait()]))

    def test_flags_geometry_and_reference_chains(self):
        for constant in (False, True):
            for io in (False, True):
                for direction in ('ExternalToLocal', 'LocalToExternal'):
                    for shape, extStride, locStride in (((17,), (1,), (1,)), ((2, 7), (12, 1), (7, 1))):
                        with self.subTest(constant=constant, io=io, direction=direction, shape=shape):
                            ctxt = context()
                            root = tensor(ctxt, 'weights' if constant else 'activation', (64,), constant)
                            root.is_input = io
                            local = ctxt.hoistReference('local', root)
                            ping = ctxt.hoistReference('ping', local)
                            pong = ctxt.hoistReference('pong', local)
                            ext = ctxt.hoistReference('external', root)
                            dma = OpenTitanAsyncDma()
                            future = dma.getFuture('x', direction)
                            op = dma.transferOpRepr(ctxt, ext, pong, shape, extStride, locStride, direction, future)
                            first = dma.transferOpRepr(ctxt, ext, ping, shape, extStride, locStride, direction, future)
                            legacy = MchanDma().transferOpRepr(ctxt, ext, local, shape, extStride, locStride, direction, future)
                            expected = (len(shape) == 2) + 2 * constant + 4 * (direction == 'ExternalToLocal') + 8 * (not io)
                            self.assertEqual(op['ot_flags'], expected)
                            self.assertEqual(op['ot_flags'], legacy['ot_flags'])
                            self.assertEqual(op['sha256'], first['sha256'])
                            self.assertEqual(op['external_base'], root.name)
                            code = dma._transferTemplates[len(shape)].generate(op)
                            self.assertLess(code.index('while (mb_read'), code.index('cl_task.transfer_id'))
                            self.assertIn('cl_task.completion_value = ++x_', code)
                            self.assertIn(f'cl_task.src_key = (uint32_t)(uintptr_t){root.name}', code)
                            self.assertIn(f'cl_task.dst_key = (uint32_t)(uintptr_t){root.name}', code)
                            self.assertIn(f'mailbox_send(1, &cl_task, {expected})', code)
                            self.assertNotIn('wait_for_idma_transfer', '\n'.join(line for line in code.splitlines() if not line.strip().startswith('//')))
                            self.assertEqual(op['size'], 17 if len(shape) == 1 else 14)
                            if len(shape) == 2:
                                self.assertEqual(op['stride_src'], 12 if direction == 'ExternalToLocal' else 7)
                                self.assertEqual(op['stride_dst'], 7 if direction == 'ExternalToLocal' else 12)

    def test_single_buffer_abi_uses_group_completion(self):
        dma = MchanDma()
        a = dma.getFuture('a', 'ExternalToLocal')
        b = dma.getFuture('b', 'ExternalToLocal')
        self.assertIs(a, b)
        self.assertIn('channel_input_submitted = 0', render([a.init()]))
        self.assertIn('channel_input_completed != channel_input_submitted', render([a.wait()]))
        self.assertIn('#else\n    wait_for_idma_transfer();', render([a.wait()]))
        ctxt = context()
        root = tensor(ctxt, 'base', (64,))
        ext = ctxt.hoistReference('external', root)
        local = ctxt.hoistReference('local', root)
        op = dma.transferOpRepr(ctxt, ext, local, (17,), (1,), (1,), 'ExternalToLocal', a)
        code = dma._transferTemplates[1].generate(op)
        self.assertLess(code.index('while (mb_read'), code.index('cl_task.transfer_id'))
        self.assertIn('cl_task.completion_value = ++channel_input_submitted', code)
        self.assertIn('cl_task.src_key = (uint32_t)(uintptr_t)base', code)

    def test_higher_rank_tickets_inside_loop(self):
        ctxt = context()
        root = tensor(ctxt, 'x', (2, 3, 4))
        ext = ctxt.hoistReference('ext', root)
        ext._memoryLevel = 'L2'
        local = ctxt.hoistReference('local', root)
        local._memoryLevel = 'L1'
        dma = OpenTitanAsyncDma()
        future = dma.getFuture('x', 'ExternalToLocal')
        code = render(AnydimAsyncDmaTransferAdapter(dma).transfer(
            ctxt, ext, local, (2, 3, 4), (24, 8, 1), (12, 4, 1), 'ExternalToLocal', future))
        self.assertLess(code.index('for ('), code.index('completion_value = ++'))
        self.assertIn('cl_task.src_stride = 8', code)
        self.assertIn('cl_task.dst_stride = 4', code)

    def test_real_double_buffer_loop(self):
        for tile_count, profiling in product((1, 2, 5), (False, True)):
            with self.subTest(tiles=tile_count, profiling=profiling):
                ctxt = context()
                constraints = NodeMemoryConstraint()
                op = {'nodeName': 'test', 'nodeOps': 42}
                # Two input futures catch the former direction-wide wait bug.
                for name in ('a', 'b', 'out'):
                    root = tensor(ctxt, name, (tile_count * 16,))
                    local = ctxt.hoistReference(name + '_local', root, (16,))
                    local._memoryLevel = 'L1'
                    op[name] = local.name
                    l2 = MemoryConstraint('L2', tile_count * 16)
                    l2.shape = (tile_count * 16,)
                    l1 = MemoryConstraint('L1', 16)
                    l1.shape = (16,)
                    l1.multiBufferCoefficient = 2
                    l1.addrSpace = (0, 32)
                    constraint = TensorMemoryConstraint(name, {'L1': l1, 'L2': l2}, ctxt)
                    dest = constraints.outputTensorMemoryConstraints if name == 'out' else constraints.inputTensorMemoryConstraints
                    dest[name] = constraint
                rectangles = [HyperRectangle((i * 16,), (16 if i < tile_count - 1 else 7,)) for i in range(tile_count)]
                schedule = TilingSchedule({'a': [0, 16], 'b': [0, 16]}, {'out': [0, 16]},
                                          [{'a': r, 'b': r} for r in rectangles], [{'out': r} for r in rectangles])
                passes = PULPClusterTiling('L2', 'L1', MchanDma())
                gen = passes.profilingDB if profiling else passes.DB
                gen._initPrefix('test')
                block = ExecutionBlock(CodeSnippet(NodeTemplate('pi_cl_team_fork(8, kernel, args);'), {}))
                ctxt, block, applied = gen.generateTilingLoop(ctxt, block, constraints, [schedule],
                                                             VariableReplacementScheme({}, {}), op)
                self.assertTrue(applied)
                code = render(block.codeSnippets)
                loop = code.index('// TILING LOOP')
                kernel = code.index('pi_cl_team_fork')
                self.assertLess(code.index('mailbox_send'), loop)  # prologue
                for name in ('a', 'b'):
                    wait = code.index(f'while ({name}_ExternalToLocal_completed', loop)
                    prefetch = code.index(f'cl_task.completion_value = ++{name}_ExternalToLocal_submitted', loop)
                    self.assertLess(wait, prefetch)
                    self.assertLess(prefetch, kernel)
                self.assertIn('switch((TILING_I+1) % 2)', code)
                self.assertIn('if ((TILING_I+1) < ', code)
                self.assertGreater(code.index('++out_LocalToExternal_submitted'), kernel)
                drain = code.rindex('while (out_LocalToExternal_completed')
                self.assertGreater(drain, code.index('// CLOSE TILING LOOP'))
                self.assertNotIn('wait_for_idma_transfer', '\n'.join(line for line in code.splitlines() if not line.strip().startswith('//')))
                # Also exercise context mangling, used by the final C emission.
                self.assertIn('pi_cl_team_fork', block.generate(ctxt))


if __name__ == '__main__':
    unittest.main()
