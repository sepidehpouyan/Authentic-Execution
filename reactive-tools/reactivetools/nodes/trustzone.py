import asyncio
import aiofile
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import contextlib
import logging
import binascii
import base64

from reactivenet import *

from reactivetools.nodes.base import Node
from ..connection import ConnectionIO
import reactivetools.tools as tools


class TrustZoneNode(Node):
    def __init__(self, name, node_number, ip_address, reactive_port, deploy_port):
        super().__init__(name, node_number, ip_address, reactive_port, deploy_port, need_lock=True)

    async def deploy(self, module):
        assert module.node is self

        if module.deployed is not None:
            return

        async with aiofile.AIOFile(await module.binary, "rb") as f:
            file_data = await f.read()
    

        uid = module.id.to_bytes(16, 'big')
        #for b in uid:
            #print(hex(b), end= ' ')
        payload = uid + file_data
        #print("---------------------------------------------------")
        #print(hex(payload[0]))
       
        command = CommandMessage(ReactiveCommand.Load,
                                Message(payload),
                                self.ip_address,
                                self.deploy_port)

        res = await self._send_reactive_command(
            command,
            log='Deploying {} on {}'.format(module.name, self.name)
            )
        
        key = RSA.import_key('''-----BEGIN RSA PRIVATE KEY-----
                    MIIBOgIBAAJBAL5c51/v1osjr5+lRPykmpQKyGdXMG0gS6Du1l8Hm0qYXc+azq6q
                    qZvr39zeufw/VLKTfeKeKVJX1D28TImn6cUCAwEAAQJASDCJGculK6zDzCHrkHeH
                    mz6fkvjwh2Go7IXGS9FhpZ6Lx6FacvAEyARdXlIYXNRogiEX3aHMQoflhOFYIMID
                    fQIhAPj4koWd11bSLeR5bI1ojNm/M7y6oKYiWlX/Txbo66L7AiEAw7y+czu2VIdK
                    qcUfGnLfI9qVrZPhw4rB14/3oOBXCj8CIQC5yINNwaLW3q/wNcuTGdlBAzSQOJN4
                    ZVoTohhaeCSd0QIgGqi0T8GMPcsHckP0zodiuOFmjXOcxiM574AeO/0SHcUCICkw
                    Ztd6hrPK/M6HFQL/fGu1MecHNrsKyroMlZNqLmXu
                    -----END RSA PRIVATE KEY-----''')

        #for a_byte in res.message.payload:
            #print(hex(a_byte), end= " ")

        print("###############################")
        sentinel = bytes(32)
        cipher = PKCS1_v1_5.new(key)
        moduel_key = cipher.decrypt(res.message.payload, sentinel)
        for a_byte in moduel_key:
            print(hex(a_byte), end= " ")
        
        print("\n")
        return moduel_key
        
    async def connect(self, to_module, conn_id):
        module_id = await to_module.get_id()
        print("=============Connect ============")
        ip = to_module.node.ip_address.packed
        for b in ip:
            print(hex(b), end= ' ')

        payload = tools.pack_int16(conn_id)                           + \
                  module_id.to_bytes(16, 'big')                       + \
                  tools.pack_int16(to_module.node.node_number)        + \
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

        module_id = await module.get_id()
        module_key = await module.key

        if conn_io == ConnectionIO.OUTPUT:
            io_id = await module.get_output_id(io_name)
        else:
            io_id = await module.get_input_id(io_name)

        nonce = self._get_nonce(module)

        ad =    tools.pack_int8(encryption)                     + \
                tools.pack_int16(conn_id)                       + \
                tools.pack_int16(io_id)                         + \
                tools.pack_int16(nonce)

        print("========================== print aad in Set-key ================\n")
        for b in key:
            print(hex(b), end= ' ')
        
        print("^^^^^^^^^^^^^^^^^^End^^^^^^^^^^^^^^^^^^^^^^\n")
        
        gcm_nonce = bytes(16)

        for b in gcm_nonce:
            print(hex(b), end= ' ')

        cipher = AES.new(module_key, AES.MODE_GCM, gcm_nonce)
        cipher.update(ad)
        ciphertext, tag = cipher.encrypt_and_digest(key)

        payload =   module_id.to_bytes(16, 'big')                     + \
                    tools.pack_int16(ReactiveEntrypoint.SetKey)       + \
                    ad                                                + \
                    ciphertext                                        + \
                    tag
        

        command = CommandMessage(ReactiveCommand.Call,
                                Message(payload),
                                self.ip_address,
                                self.reactive_port)

        print("command ready\n")
        
        await self._send_reactive_command(
                command,
                log='Setting key of connection {} ({}:{}) on {} to {}'.format(
                     conn_id, module.name, io_name, self.name,
                     binascii.hexlify(key).decode('ascii'))
                )

    async def call(self, module, entry, arg=None):
        assert module.node is self

        module_id = await module.get_id()
        entry_id = await module.get_entry_id(entry)

        print("========================== Call ================\n")

        payload = module_id.to_bytes(16, 'big') + \
                  tools.pack_int16(entry_id)  + \
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
