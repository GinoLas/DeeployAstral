# SPDX-FileCopyrightText: 2024 ETH Zurich and University of Bologna
#
# SPDX-License-Identifier: Apache-2.0

from typing import Tuple

from Deeploy.DeeployTypes import CodeGenVerbosity, CodeTransformationPass, ExecutionBlock, NetworkContext, _NoVerbosity
from Deeploy.Targets.PULPOpen.DMA.MchanDma import MchanDma
from Deeploy.Targets.PULPOpen.DMA.OpenTitanAsyncDma import OpenTitanAsyncDma
from Deeploy.TilingExtension.AsyncDma import AsyncDma
from Deeploy.TilingExtension.CodeTransformationPasses.DoubleBufferingTilingCodeGeneration import \
    DoubleBufferingTilingCodeGeneration, ProfilingDoubleBufferingTilingMixIn
from Deeploy.TilingExtension.CodeTransformationPasses.SingleBufferingTilingCodeGeneration import \
    ProfilingSingleBufferingTilingMixIn, SingleBufferingTilingCodeGeneration


class PULPClusterTilingGenerationSB(SingleBufferingTilingCodeGeneration):
    pass


class ProfilingPULPClusterTilingGenerationSB(SingleBufferingTilingCodeGeneration, ProfilingSingleBufferingTilingMixIn):
    pass


class PULPClusterTilingGenerationDB(DoubleBufferingTilingCodeGeneration):
    pass


class ProfilingPULPClusterTilingGenerationDB(DoubleBufferingTilingCodeGeneration, ProfilingDoubleBufferingTilingMixIn):
    pass


class PULPClusterTiling(CodeTransformationPass):

    def __init__(self, externalMemory: str, localMemory: str, dma: AsyncDma):
        self.SB = PULPClusterTilingGenerationSB(externalMemory, localMemory, dma)
        self.profilingSB = ProfilingPULPClusterTilingGenerationSB(externalMemory, localMemory, dma)
        # The legacy global completion event cannot represent concurrent tiles.
        dbDma = OpenTitanAsyncDma() if type(dma) is MchanDma else dma
        self.DB = PULPClusterTilingGenerationDB(externalMemory, localMemory, dbDma)
        self.profilingDB = ProfilingPULPClusterTilingGenerationDB(externalMemory, localMemory, dbDma)



    def apply(self,
              ctxt: NetworkContext,
              executionBlock: ExecutionBlock,
              name: str,
              verbose: CodeGenVerbosity = _NoVerbosity) -> Tuple[NetworkContext, ExecutionBlock]:
        
        if verbose.tilingProfiling:
            ctxt, executionBlock = self.profilingSB.apply(ctxt, executionBlock, name)
            ctxt, executionBlock = self.profilingDB.apply(ctxt, executionBlock, name)
        else:
            ctxt, executionBlock = self.SB.apply(ctxt, executionBlock, name)
            ctxt, executionBlock = self.DB.apply(ctxt, executionBlock, name)

        return ctxt, executionBlock
