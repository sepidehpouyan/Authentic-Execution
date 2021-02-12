import logging
import tempfile
import os
import asyncio
import base64
import struct


class ProcessRunError(Exception):
    def __init__(self, args, result):
        self.args = args
        self.result = result

    def __str__(self):
        return 'Command "{}" exited with code {}' \
                    .format(' '.join(self.args), self.result)


class Error(Exception):
    pass


def init_future(*results):
    if all(map(lambda x: x is None, results)):
        return None

    fut = asyncio.Future()
    result = results[0] if len(results) == 1 else results
    fut.set_result(result)
    return fut


async def run_async(*args):
    logging.debug(' '.join(args))
    process = await asyncio.create_subprocess_exec(*args)
    result = await process.wait()

    if result != 0:
        raise ProcessRunError(args, result)


async def run_async_muted(*args, output_file=os.devnull):
    logging.debug(' '.join(args))
    process = await asyncio.create_subprocess_exec(*args,
                                            stdout=open(output_file, 'wb'),
                                            stderr=asyncio.subprocess.STDOUT)
    result = await process.wait()

    if result != 0:
        raise ProcessRunError(args, result)


async def run_async_background(*args):
    logging.debug(' '.join(args))
    process = await asyncio.create_subprocess_exec(*args,
                                            stdout=open(os.devnull, 'wb'),
                                            stderr=asyncio.subprocess.STDOUT)

    return process


async def run_async_output(*args):
    cmd = ' '.join(args)
    logging.debug(cmd)
    process = await asyncio.create_subprocess_exec(*args,
                                            stdout=asyncio.subprocess.PIPE,
                                            stderr=asyncio.subprocess.PIPE)
    out, err = await process.communicate()

    if err:
        raise Error('cmd "{}" error: {}'.format(cmd, err))

    return out


async def run_async_shell(*args):
    cmd = ' '.join(args)
    logging.debug(cmd)
    process = await asyncio.create_subprocess_shell(cmd,
                                            stdout=open(os.devnull, 'wb'),
                                            stderr=asyncio.subprocess.STDOUT)
    result = await process.wait()

    if result != 0:
        raise ProcessRunError(args, result)


def create_tmp(suffix=''):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def create_tmp_dir():
    return tempfile.mkdtemp()


def generate_key(length):
    return os.urandom(length)


def pack_int8(i):
    return struct.pack('!B', i)

def unpack_int8(i):
    return struct.unpack('!B', i)[0]

def pack_int16(i):
    return struct.pack('!H', i)

def unpack_int16(i):
    return struct.unpack('!H', i)[0]

def pack_int32(i):
    return struct.pack('!I', i)

def unpack_int32(i):
    return struct.unpack('!I', i)[0]
