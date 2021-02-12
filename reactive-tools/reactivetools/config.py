import json
import binascii
import ipaddress
from pathlib import Path
import os
import asyncio
import functools
import binascii
import types
import logging

from reactivetools.nodes.trustzone import TrustZoneNode
from reactivetools.modules.trustzone import TrustZoneModule
from reactivetools.connection import Connection, Encryption
from reactivetools.periodic_event import PeriodicEvent
import reactivetools.tools as tools


class Error(Exception):
    pass


class Config:
    def __init__(self, file_name):
        self.path = Path(file_name).resolve()
        self.nodes = []
        self.modules = []
        self.connections = []

    def get_dir(self):
        return self.path.parent

    def get_node(self, name):
        for n in self.nodes:
            if n.name == name:
                return n

        raise Error('No node with name {}'.format(name))

    def get_module(self, name):
        for m in self.modules:
            if m.name == name:
                return m

        raise Error('No module with name {}'.format(name))

# ===============================================================================

    async def deploy_priority_modules(self):
        priority_modules = [sm for sm in self.modules if sm.priority is not None]
        priority_modules.sort(key=lambda sm : sm.priority)

        logging.debug("Priority modules: {}".format([sm.name for sm in priority_modules]))
        
        for module in priority_modules:
            await module.deploy()

    async def install_async(self):
        await self.deploy_priority_modules()

        await self.deploy_modules_ordered_async()

        futures = map(Connection.establish, self.connections)
        await asyncio.gather(*futures)

        futures = map(PeriodicEvent.register, self.periodic_events)
        await asyncio.gather(*futures)

    def install(self):
        asyncio.get_event_loop().run_until_complete(self.install_async())

    async def deploy_modules_ordered_async(self):
        for module in self.modules:
            await module.deploy()

    def deploy_modules_ordered(self):
        asyncio.get_event_loop().run_until_complete(
                                self.deploy_modules_ordered_async())

def load(file_name):
    with open(file_name, 'r') as f:
        contents = json.load(f)

    config = Config(file_name)

    config.nodes = _load_list(contents['nodes'], _load_node)
    config.modules = _load_list(contents['modules'],
                                lambda m: _load_module(m, config))

    try:
        config.connections = _load_list(contents['connections'],
                                        lambda c: _load_connection(c, config))
    except Exception as e:
        logging.warning("Error while loading 'connections' section of input file")
        logging.warning("{}".format(e))
        config.connections = []

    try:
        config.periodic_events = _load_list(contents['periodic-events'],
                                        lambda e: _load_periodic_event(e, config))
    except Exception as e:
        logging.warning("Error while loading 'periodic-events' section of input file")
        logging.warning("{}".format(e))
        config.periodic_events = []

    return config


def _load_list(l, load_func=lambda e: e):
    if l is None:
        return []
    else:
        return [load_func(e) for e in l]

def _load_node(node_dict):
    return _node_load_funcs[node_dict['type']](node_dict)

def _load_trustzone_node(node_dict):
    name = node_dict['name']
    node_number = node_dict['number']
    ip_address = ipaddress.ip_address(node_dict['ip_address'])
    reactive_port = node_dict['reactive_port']
    deploy_port = node_dict.get('deploy_port', reactive_port)

    return TrustZoneNode(name, node_number, ip_address, reactive_port, deploy_port)

def _load_module(mod_dict, config):
    return _module_load_funcs[mod_dict['type']](mod_dict, config)

def _load_trustzone_module(mod_dict, config):
    name = mod_dict['name']
    node = config.get_node(mod_dict['node'])
    priority = mod_dict.get('priority')
    deployed = mod_dict.get('deployed')
    files = mod_dict.get('files')
    binary = mod_dict.get('binary')
    id = mod_dict.get('id')
    key = _parse_module_key(mod_dict.get('key'))
    inputs = mod_dict.get('inputs')
    #print("inputs: ", type(inputs), inputs["input"]) #*******************************
    outputs = mod_dict.get('outputs')
    entrypoints = mod_dict.get('entrypoints')
    return TrustZoneModule(name, node, priority, deployed, files, binary, id, key, inputs, outputs,
                    entrypoints)

def _load_connection(conn_dict, config):
    from_module = config.get_module(conn_dict['from_module'])
    from_output = conn_dict['from_output']
    to_module = config.get_module(conn_dict['to_module'])
    to_input = conn_dict['to_input']
    encryption = Encryption.from_str(conn_dict['encryption'])

    if from_module == to_module:
        raise Error("Cannot establish a within the same module!")

    from_module.connections += 1
    to_module.connections += 1

    if 'key' in conn_dict:
        key = conn_dict['key']
    else:
        key = _generate_key(from_module, to_module, encryption)
    return Connection(from_module, from_output, to_module, to_input, encryption, key)

def _load_periodic_event(events_dict, config):
    module = config.get_module(events_dict['module'])
    entry = events_dict['entry']
    frequency = _parse_frequency(events_dict['frequency'])

    return PeriodicEvent(module, entry, frequency)


def _generate_key(module1, module2, encryption):
    if encryption not in module1.get_supported_encryption() or \
       encryption not in module2.get_supported_encryption():
       raise Error('Encryption "{}" not supported between {} and {}'.format(
            encryption, module1.name, module2.name))
    
    #print("hellooooooo####", type(tools.generate_key(encryption.get_key_size())))
    #for a_byte in tools.generate_key(encryption.get_key_size()):
            #print(hex(a_byte), end= " ")
    return tools.generate_key(encryption.get_key_size())


def _parse_module_key(key_str):
    if key_str is None:
        return None

    key = binascii.unhexlify(key_str)

    return key


def _parse_frequency(freq):
    if not 1 <= freq <= 2**32 - 1:
        raise Error('Frequency out of range')

    return freq


_node_load_funcs = {
    'trustzone': _load_trustzone_node
}


_module_load_funcs = {
    'trustzone': _load_trustzone_module
}


def dump(config, file_name):
    with open(file_name, 'w') as f:
        json.dump(_dump(config), f, indent=4)


@functools.singledispatch
def _dump(obj):
    assert False, 'No dumper for {}'.format(type(obj))


@_dump.register(Config)
def _(config):
    return {
        'nodes': _dump(config.nodes),
        'modules': _dump(config.modules),
        'connections': _dump(config.connections),
        'periodic-events' : _dump(config.periodic_events)
    }


@_dump.register(list)
def _(l):
    return [_dump(e) for e in l]


@_dump.register(TrustZoneNode)
def _(node):
    return {
        "type": "trustzone",
        "name": node.name,
        "number": node.node_number,
        "ip_address": str(node.ip_address),
        "reactive_port": node.reactive_port,
        "deploy_port": node.deploy_port
    }

@_dump.register(TrustZoneModule)
def _(module):
    return {
        "type": "trustzone",
        "name": module.name,
        "files": module.files,
        "node": module.node.name,
        "binary": _dump(module.binary),
        "id": module.id,
        "key": _dump(module.key),
        "inputs":module.inputs,
        "outputs":module.outputs,
        "entrypoints":module.entrypoints

    }

@_dump.register(Connection)
def _(conn):
    return {
        "from_module": conn.from_module.name,
        "from_output": conn.from_output,
        "to_module": conn.to_module.name,
        "to_input": conn.to_input,
        "encryption": conn.encryption.to_str(),
        "key": _dump(conn.key)
    }


@_dump.register(PeriodicEvent)
def _(event):
    return {
        "module": event.module.name,
        "entry": event.entry,
        "frequency": event.frequency
    }


@_dump.register(bytes)
@_dump.register(bytearray)
def _(bs):
    return binascii.hexlify(bs).decode('ascii')


@_dump.register(str)
@_dump.register(int)
def _(x):
    return x


@_dump.register(Path)
def _(path):
    return str(path)


@_dump.register(tuple)
def _(t):
    return { t[1] : t[0] }


@_dump.register(types.CoroutineType)
def _(coro):
    return _dump(asyncio.get_event_loop().run_until_complete(coro))


@_dump.register(dict)
def _(dict):
    return dict
