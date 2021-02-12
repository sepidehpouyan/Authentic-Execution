import asyncio
import aiofiles
import logging
from enum import Enum
import uuid
import os

from reactivetools.modules.base import Module
from reactivetools.connection import Encryption
import reactivetools.tools as tools

class Error(Exception):
    pass


class TrustZoneModule(Module):
    
    def __init__(self, name, node, priority, deployed, files,
                 binary=None, id=None, key=None, inputs=None, outputs=None,
                    entrypoints=None):
        super().__init__(name, node, priority, deployed)

        self.files = files
        self.id = id
        self.inputs =  inputs
        self.outputs =  outputs
        self.entrypoints =  entrypoints

        self.uuid_for_MK = ""

        self.__build_fut = tools.init_future(binary)
        self.__deploy_fut = tools.init_future(key)

      
    # --- Properties --- #
    @property
    async def binary(self):
        if self.__build_fut is None:
            self.__build_fut = asyncio.ensure_future(self.__build())

        return await self.__build_fut

    @property
    async def key(self):
        key = await self.deploy()
        return key

 # --- Implement abstract methods --- #

    async def deploy(self):
        if self.__deploy_fut is None:
            self.__deploy_fut = asyncio.ensure_future(self.node.deploy(self))

        return await self.__deploy_fut

    async def call(self, entry, arg=None):
        return await self.node.call(self, entry, arg)


    async def get_id(self):
        return self.id

    
    async def get_input_id(self, input):
        # If io is a number, that is the ID (given by the deployer)
        if isinstance(input, int):
            return input

        inputs = self.inputs

        if input not in inputs:
            raise Error("Input not present in inputs")

        return inputs[input]


    async def get_output_id(self, output):
        if isinstance(output, int):
            return output

        outputs = self.outputs

        if output not in outputs:
            raise Error("Output not present in outputs")

        return outputs[output]


    async def get_entry_id(self, entry):
        if isinstance(entry, int):
            return entry

        entrypoints = self.entrypoints

        if entry not in entrypoints:
            raise Error("Entry not present in entrypoints")

        return entrypoints[entry]

 # --- Static methods --- #

    @staticmethod
    def get_supported_encryption():
        return [Encryption.AES, Encryption.SPONGENT]

 # --- Other methods --- #       

    async def __build(self):

        print(self.id)
        hex = '%032x' % (self.id)
        self.uuid_for_MK = '%s-%s-%s-%s-%s' % (hex[:8], hex[8:12], hex[12:16], hex[16:20], hex[20:])
        print(self.uuid_for_MK)

        binary = ""

        compiler = "CROSS_COMPILE=/home/sepideh/optee-qemu/toolchains/aarch32/bin/arm-linux-gnueabihf-"
        plat = "PLATFORM=vexpress-qemu_virt"
        dev_kit = "TA_DEV_KIT_DIR=/home/sepideh/optee-qemu/optee_os/out/arm/export-ta_arm32"
        binary_name = "BINARY=" + self.uuid_for_MK

        cmd = "make -C " + self.files + "/" + self.name + " " + compiler + " " + plat + \
             " " + dev_kit + " " + binary_name

        await tools.run_async_shell(cmd)

        binary = self.files + "/" + self.name + "/" + self.uuid_for_MK + ".ta"

        return binary

# --- @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ --- #