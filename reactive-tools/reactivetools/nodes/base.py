import asyncio
import struct
import collections
import logging

from abc import ABC, abstractmethod
from enum import IntEnum


class Error(Exception):
    pass

class Node(ABC):
    def __init__(self, name, node_number, ip_address, reactive_port, deploy_port, need_lock=False):
        self.name = name
        self.node_number = node_number
        self.ip_address = ip_address
        self.reactive_port = reactive_port
        self.deploy_port = deploy_port

        self.__nonces = collections.Counter()

        if need_lock:
            self.__lock = asyncio.Lock()
        else:
            self.__lock = None

    @abstractmethod
    async def deploy(self, module):
        pass

    @abstractmethod
    async def connect(self, to_module, conn_id):
        pass

    @abstractmethod
    async def set_key(self, module, conn_id, io_name, encryption, key, conn_io):
        pass

    @abstractmethod
    async def call(self, module, entry, arg=None):
        pass

    #####===========================================================================

    async def _send_reactive_command(self, command, log=None):
        if self.__lock is not None:
            async with self.__lock:
                return await self.__send_reactive_command(command, log)
        else:
            return await self.__send_reactive_command(command, log)


    @staticmethod
    async def __send_reactive_command(command, log):
        if log is not None:
            logging.info(log)

        if command.has_response():
            print("has response")
            response =  await command.send_wait()
            if not response.ok():
                raise Error('Reactive command {} failed with code {}'
                                .format(str(command.code), str(response.code)))
            return response

        else:
            await command.send()
            return None

    # ==================================================================================
    
    def _get_nonce(self, module):
        nonce = self.__nonces[module]
        self.__nonces[module] += 1
        return nonce
