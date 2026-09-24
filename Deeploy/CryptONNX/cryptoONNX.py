import onnx
import onnx_graphsurgeon as gs
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import secrets
import base64
 
class ONNXEncryptor:
    def __init__(self, key_hex: str, hmac_key_hex: str):
        self.key = bytes.fromhex(key_hex)
        self.hmac_key = bytes.fromhex(hmac_key_hex)
        self.key_hex = key_hex
        self.hmac_key_hex = hmac_key_hex
        self.backend = default_backend()
 
    def _encrypt_weights(self, data_numpy: np.ndarray, iv) -> np.ndarray:
        raw_bytes = data_numpy.tobytes()
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(raw_bytes) + encryptor.finalize()
 
        return np.frombuffer(encrypted_data, dtype=np.uint8)
   
    def _encrypt_biases(self, data_numpy: np.ndarray, iv) -> np.ndarray:
        raw_bytes = data_numpy.tobytes()
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(raw_bytes) + encryptor.finalize()
 
        return np.frombuffer(encrypted_data, dtype=np.uint32)
 
    def process_graph(self, graph: gs.Graph) -> gs.Graph:
        """
        Prende un oggetto gs.Graph, cifra i pesi e aggiunge come attributo ai nodi HMAAC sui pesi.
        """
 
        print(f"hmac_key = {self.hmac_key}")
        print(f"Key = {self.key}")
 
        #Aggiunta delle due chiavi al grafo come attributo python
 
        print("Adding keys...")
 
        graph.hmac_key = self.hmac_key_hex
        graph.aes_key = self.key_hex
 
        for node in graph.nodes:
            if len(node.inputs) > 1:
                for input in node.inputs:
                    if isinstance(input, gs.Constant):
                       
                        # Weights
                        if "weight_tensor" in input.name:
                            shape = input.values.shape
                            weights_tensor = np.array(input.values,dtype = np.int8)
                            # weights_tensor = weights_tensor.transpose(0,2,3,1)
 
                            # for i, byte in enumerate(weights_tensor.flatten()):
                            #     print(str(byte),end="\t")
                           
                            #     if (i + 1) % 8 == 0:
                            #         print(",")  
                            #     else:
                            #         print(", ",end="")
                            iv = secrets.token_bytes(16)
                            print(iv.hex())
                            encrypted_bytes = self._encrypt_weights(weights_tensor,iv)
                            encrypted_bytes = encrypted_bytes.reshape(weights_tensor.shape)
                            digest = hmac.new(self.hmac_key, np.ascontiguousarray(encrypted_bytes), hashlib.sha256).digest()
                            hmac_array = np.frombuffer(digest,dtype=np.uint32)
                            # input.values = np.array(encrypted_bytes.transpose(0,3,1,2),dtype = np.int8)
                            input.values = np.array(encrypted_bytes,dtype = np.int8)
                            input.values = input.values.reshape(shape)
                            if('hmac' not in node.attrs):
                                node.attrs['hmac'] = True
                            node.attrs[f"{input.name}_hmac"] = (gs.Constant(
                                name = f"{input.name}_hmac",
                                values = hmac_array
                            ))
                            node.attrs[f"{input.name}_iv"] = (gs.Constant(
                                name = f"{input.name}_iv",
                                values = np.frombuffer(iv,dtype=np.uint8)
                            ))
 
                        # MatMul constants
                        elif "MatMul" in input.name or (hasattr(input, 'name') and "fc" in input.name):
                            shape = input.values.shape
                            weights_tensor = np.array(input.values, dtype=np.int8)
                            iv = secrets.token_bytes(16)
                            print(iv.hex())
                            encrypted_bytes = self._encrypt_weights(weights_tensor,iv)
                            encrypted_bytes.shape = weights_tensor.shape
                            digest = hmac.new(self.hmac_key, np.ascontiguousarray(encrypted_bytes), hashlib.sha256).digest()
                            hmac_array = np.frombuffer(digest,dtype=np.uint32)
                            input.values = np.array(encrypted_bytes,dtype = np.int32)
                            input.values = input.values.reshape(shape)
                            if('hmac' not in node.attrs):
                                node.attrs['hmac'] = True
                            node.attrs[f"{input.name}_hmac"] = (gs.Constant(
                                name = f"{input.name}_hmac",
                                values = hmac_array
                            ))
                            node.attrs[f"{input.name}_iv"] = (gs.Constant(
                                name = f"{input.name}_iv",
                                values = np.frombuffer(iv,dtype=np.uint8)
                            ))
                           
                            input.values = np.array(encrypted_bytes, dtype=np.int8)
 
                        # Biases
                        elif "mul_tensor" in input.name or "add_tensor" in input.name or "bias_tensor" in input.name:
                            shape = input.values.shape
                            weights_tensor = np.array(input.values,dtype = np.int32)
                            iv = secrets.token_bytes(16);
                            print(iv.hex())
                            encrypted_bytes = self._encrypt_biases(weights_tensor,iv)
                            encrypted_bytes = encrypted_bytes.reshape(weights_tensor.shape)
                            digest = hmac.new(self.hmac_key, np.ascontiguousarray(encrypted_bytes), hashlib.sha256).digest()
                            hmac_array = np.frombuffer(digest,dtype=np.uint32)
                            # input.values = np.array(encrypted_bytes.transpose(0,3,1,2),dtype = np.int8)
                            input.values = np.array(encrypted_bytes,dtype = np.int32)
                            input.values = input.values.reshape(shape)
                            if('hmac' not in node.attrs):
                                node.attrs['hmac'] = True
                            node.attrs[f"{input.name}_hmac"] = (gs.Constant(
                                name = f"{input.name}_hmac",
                                values = hmac_array
                            ))
                            node.attrs[f"{input.name}_iv"] = (gs.Constant(
                                name = f"{input.name}_iv",
                                values = np.frombuffer(iv,dtype=np.uint8)
                            ))
 
 
        return graph.cleanup().toposort()