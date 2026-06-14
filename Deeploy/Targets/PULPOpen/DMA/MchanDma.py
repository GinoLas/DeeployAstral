# SPDX-FileCopyrightText: 2025 ETH Zurich and University of Bologna
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import math
from typing import Dict, Tuple

from Deeploy.DeeployTypes import NetworkContext, NodeTemplate, OperatorRepresentation, VariableBuffer, TransientBuffer, ConstantBuffer
from Deeploy.TilingExtension.AsyncDma import AsyncDma, DirectionWaitingStrategy, DmaDirection, Future

counter = 0

hash_counter = {}


class MchanChannelFuture(Future):

    _initTemplate = NodeTemplate("")

    _deinitTemplate = NodeTemplate("")

    _allocTemplate = NodeTemplate("")

    _waitTemplate = NodeTemplate("""
""")
    

def calcola_sha256(testo):
    testo_in_byte = testo.encode('utf-8')
    
    hash_object = hashlib.sha256(testo_in_byte)
    
    hash_esadecimale = hash_object.hexdigest()
    
    return hash_esadecimale
    




class MchanDma(AsyncDma):

    _transferTemplates = {
        1: NodeTemplate("""
                        //sha256 = ${sha256}
                        //bufferHash = ${bufferHash}
                        cl_task.transfer_id = 0x${sha256};
                        cl_task.size = ${size};
                        cl_task.src = ${loc};
                        cl_task.dst = ${ext};
                        //Hashmap keys 
                        mailbox_send(1,&cl_task,${ot_flags});
                        mb_write(0x1, MBOX_CAR_INT_SND_SET(1));
                        //partial_size_${sha256} += cl_task.size;
                        wait_for_idma_transfer();

                        """),
        2: NodeTemplate("""
                        //sha256 = ${sha256}
                        //bufferHash = ${bufferHash}
                        //${size_1d}
                        //cl_task.bufferHash = 0x${bufferHash};
                        cl_task.transfer_id = 0x${sha256};
                        cl_task.size = ${size};
                        cl_task.src = ${loc};
                        cl_task.dst = ${ext};
                        cl_task.src_stride = ${stride_src};
                        cl_task.dst_stride = ${stride_dst};
                        cl_task.repetitions = ${repetitions};
                        cl_task.size_1d = ${size_1d};
                        mailbox_send(1,&cl_task,${ot_flags});
                        mb_write(0x1, MBOX_CAR_INT_SND_SET(1));
                        wait_for_idma_transfer();
                        """),
    }
    _waitingStrategy = DirectionWaitingStrategy(MchanChannelFuture, "channel")

    def __init__(self, transferTemplates: Dict[int, NodeTemplate] = _transferTemplates) -> None:
        super().__init__(transferTemplates)

    def checkTransfer(self, ctxt: NetworkContext, externalBuffer: VariableBuffer, localBuffer: VariableBuffer,
                      shape: Tuple[int, ...], strideExt: Tuple[int, ...], strideLoc: Tuple[int, ...],
                      direction: DmaDirection) -> None:
        super().checkTransfer(ctxt, externalBuffer, localBuffer, shape, strideExt, strideLoc, direction)

        transferRank = len(shape)
        assert strideExt[
            -1] == 1, "Mchan supports only contigous transfers of the innermost dimension for external memory"
        if transferRank == 1:
            assert strideLoc[0] == 1, "Mchan supports only contigous transfers for local memory"
        else:
            assert strideLoc[0] == shape[1] and strideLoc[
                1] == 1, "Mchan supports only contigous transfers for local memory"

    def transferOpRepr(self,ctxt : NetworkContext, externalBuffer: VariableBuffer, localBuffer: VariableBuffer, shape: Tuple[int, ...],
                       strideExt: Tuple[int, ...], strideLoc: Tuple[int, ...], direction: DmaDirection,
                       future: Future) -> OperatorRepresentation:
        operatorRepresentation = super().transferOpRepr(externalBuffer, localBuffer, shape, strideExt, strideLoc,
                                                        direction, future)

        is_input = ctxt.lookup(externalBuffer._referenceName).is_input or ctxt.lookup(localBuffer._referenceName).is_input
        is_output = ctxt.lookup(externalBuffer._referenceName).is_output or ctxt.lookup(localBuffer._referenceName).is_output

        transferRank = len(shape)

        mchanFlags = 0
        mchanFlags += (1 << 0) if direction == "ExternalToLocal" else 0  # direction
        mchanFlags += (1 << 1)  # increment addresses
        mchanFlags += (1 << 2) if transferRank == 2 else 0  # 2d transfer
        mchanFlags += (1 << 3)  # event enable

        mchanTransferSize = math.prod(shape)
        mchanTransferSizeBits = math.ceil(math.log2(mchanTransferSize))
        assert mchanTransferSizeBits <= 17, (
            "The transfer size is not representable with 17 bits. "
            f"Received transfer size {mchanTransferSize} that requires {mchanTransferSizeBits}")

        operatorRepresentation["cmd"] = (mchanFlags << 17) + mchanTransferSize

        operatorRepresentation["size"] = mchanTransferSize

        

        '''

        - Tipo di trasferimento (pesi, attivazioni)
        - Tipo di operazione (cifratura, decifratura)
        - Geometria trasferimento (1d,2d [3d?])

        bit[0] -> geometria trasferimento (0 = 1d, 1 = 2d) 
        bit[1] -> Flag pesi (0 = attivazioni, 1 = pesi)
        bit[2] -> Tipo di operazione (0 = cifratura, 1 = decifratura)
        bit[3] -> Attiva operazione (0 = solo spostamento, 1 = considera il bit 2)
        bit[4] -> Clear della hashmap

        '''

        OTflags = 0


        if(direction == "ExternalToLocal"):
            OTflags += (1 << 2)
            tmp = operatorRepresentation["loc"]
            operatorRepresentation["loc"] = operatorRepresentation["ext"]
            operatorRepresentation["ext"] = tmp

        testo = operatorRepresentation["loc"]+operatorRepresentation["ext"]

        bufferHash = calcola_sha256(localBuffer._referenceName)[0:8]

        operatorRepresentation["bufferHash"] = bufferHash


        sha = calcola_sha256(testo)

        if(sha not in hash_counter.keys()):
            global counter
            counter += 1
            hash_counter[sha] = counter

        

        operatorRepresentation["sha256"] = calcola_sha256(testo)[0:8]


        if transferRank == 2:   
            OTflags += (1 << 0)
            operatorRepresentation["repetitions"] = (int)(mchanTransferSize / shape[1])
            operatorRepresentation["size_1d"] = shape[1]
            operatorRepresentation["stride_2d"] = strideExt[0]
            if(direction == "ExternalToLocal"):
                operatorRepresentation["stride_src"] = strideExt[0]
                operatorRepresentation["stride_dst"] = strideLoc[0]
            else:
                operatorRepresentation["stride_dst"] = strideExt[0]
                operatorRepresentation["stride_src"] = strideLoc[0]


        # if("weight" in externalBuffer.name or "weight" in localBuffer.name):
        if(isinstance(ctxt.lookup(externalBuffer._referenceName),ConstantBuffer)):
            OTflags += (1 << 1)

        old_size = mchanTransferSize

        
        if( (not is_input) and (not is_output)):
            if(mchanTransferSize % 16 != 0):
                mchanTransferSize += 16 - mchanTransferSize%16
            # if("mul_tensor" not in externalBuffer.name and "add_tensor" not in externalBuffer.name):
            OTflags += (1 << 3)
            # print(operatorRepresentation["sha256"]+ "-->" + " NOT input/output")
        # else:
            # print(operatorRepresentation["sha256"]+ "-->" + " input/output")

        


        # print(str(old_size) + "->" + str(mchanTransferSize))

        operatorRepresentation["ot_flags"] = OTflags
        




        return operatorRepresentation
