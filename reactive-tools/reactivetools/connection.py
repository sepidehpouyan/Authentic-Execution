from collections import namedtuple
import asyncio
import logging
from enum import IntEnum

from . import tools

class Error(Exception):
    pass

class Connection(namedtuple('Connection', ['from_module', 'from_output',
                                           'to_module', 'to_input',
                                           'encryption', 'key'])):
    id = 0
    async def establish(self):
        from_node, to_node = self.from_module.node, self.to_module.node
        conn_id = self.get_connection_id()

        # TODO check if the module is the same: if so, abort!
        connect = from_node.connect(self.to_module, conn_id)
        
        set_key_from = from_node.set_key(self.from_module, conn_id, self.from_output,
                                     self.encryption, self.key, ConnectionIO.OUTPUT)
                    
        set_key_to = to_node.set_key(self.to_module, conn_id, self.to_input,
                                     self.encryption, self.key, ConnectionIO.INPUT)

        await asyncio.gather(connect, set_key_from, set_key_to)

        logging.info('Connection %d from %s:%s on %s to %s:%s on %s established',
                     conn_id, self.from_module.name, self.from_output, from_node.name,
                     self.to_module.name, self.to_input, to_node.name)
        

    @staticmethod
    def get_connection_id():
        id = Connection.id
        Connection.id += 1
        return id


class ConnectionIO(IntEnum):
    OUTPUT  = 0x0
    INPUT   = 0x1


class Encryption(IntEnum):
    AES         = 0x0
    SPONGENT    = 0x1

    @staticmethod
    def from_str(str):
        lower_str = str.lower()

        if lower_str == "aes":
            return Encryption.AES
        if lower_str == "spongent":
            return Encryption.SPONGENT

        raise Error("No matching encryption type for {}".format(str))

    def to_str(self):
        if self == Encryption.AES:
            return "aes"
        if self == Encryption.SPONGENT:
            return "spongent"

    def get_key_size(self):
        if self == Encryption.AES:
            return 16
        if self == Encryption.SPONGENT:
            return tools.get_sancus_key_size()
