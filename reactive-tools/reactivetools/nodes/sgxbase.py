import asyncio
import logging
from abc import ABC, abstractmethod
import base64
import contextlib
import binascii

from reactivenet import *

from .base import Node
from ..connection import ConnectionIO
from .. import glob
from .. import tools

class Error(Exception):
    pass


class SGXBase(Node):
    def __init__(self, name, ip_address, reactive_port, deploy_port):
        super().__init__(name, ip_address, reactive_port, deploy_port)

        self.__moduleid = 1


    @abstractmethod
    async def deploy(self, module):
        pass


    async def connect(self, to_module, conn_id):
        module_id = await to_module.get_id()

        payload = tools.pack_int16(conn_id)                           + \
                  tools.pack_int16(module_id)                         + \
                  tools.pack_int16(to_module.node.reactive_port)      + \
                  to_module.node.ip_address.packed

        command = CommandMessage(ReactiveCommand.Connect,
                                Message(payload),
                                self.ip_address,
                                self.reactive_port)

        await self._send_reactive_command(
                command,
                log='Connecting id {} to {}'.format(conn_id, to_module.name))


    async def set_key(self, module, conn_id, io_name, encryption, key, conn_io):
        assert module.node is self
        assert encryption in module.get_supported_encryption()
        await module.deploy()

        if conn_io == ConnectionIO.OUTPUT:
            io_id = await module.get_output_id(io_name)
        else:
            io_id = await module.get_input_id(io_name)

        nonce = self._get_nonce(module)

        ad =    tools.pack_int8(encryption)                     + \
                tools.pack_int16(conn_id)                       + \
                tools.pack_int16(io_id)                         + \
                tools.pack_int16(nonce)

        # encrypting key
        args = [base64.b64encode(ad).decode(), base64.b64encode(key).decode(),
                                    base64.b64encode(await module.key).decode()]

        out = await tools.run_async_output(glob.ENCRYPTOR, *args)

        cipher = base64.b64decode(out)

        payload =   tools.pack_int16(module.id)                     + \
                    tools.pack_int16(ReactiveEntrypoint.SetKey)     + \
                    ad                                              + \
                    cipher

        command = CommandMessage(ReactiveCommand.Call,
                                Message(payload),
                                self.ip_address,
                                self.reactive_port)

        await self._send_reactive_command(
                command,
                log='Setting key of connection {} ({}:{}) on {} to {}'.format(
                     conn_id, module.name, io_name, self.name,
                     binascii.hexlify(key).decode('ascii'))
                )


    async def call(self, module, entry, arg=None):
        assert module.node is self
        module_id = module.id
        entry_id = await module.get_entry_id(entry)

        payload = tools.pack_int16(module_id)       + \
                  tools.pack_int16(entry_id)        + \
                  (b'' if arg is None else arg)

        command = CommandMessage(ReactiveCommand.Call,
                                Message(payload),
                                self.ip_address,
                                self.reactive_port)

        await self._send_reactive_command(
                command,
                log='Sending call command to {}:{} ({}:{}) on {}'.format(
                     module.name, entry, module_id, entry_id, self.name)
                )


    async def register_entrypoint(self, module, entry, frequency):
        assert module.node is self
        module_id = module.id
        entry_id = await module.get_entry_id(entry)

        payload = tools.pack_int16(module_id)       + \
                  tools.pack_int16(entry_id)        + \
                  tools.pack_int32(frequency)

        command = CommandMessage(ReactiveCommand.RegisterEntrypoint,
                                Message(payload),
                                self.ip_address,
                                self.reactive_port)

        await self._send_reactive_command(
                command,
                log='Sending RegisterEntrypoint command of {}:{} ({}:{}) on {}'.format(
                     module.name, entry, module_id, entry_id, self.name)
                )


    def get_module_id(self):
        id = self.__moduleid
        self.__moduleid += 1

        return id
