import asyncio
import subprocess
import os
import sys
import signal

SOC_TERM    = "soc_term"
BUILD       = "/opt/optee/build"
LOGS        = "/opt/optee/logs"


async def main():
    os.chdir(BUILD)

    log_file = "{}/log_{}.txt".format(LOGS, os.environ['PORT'])

    # To print the SW output on a file, add: stdout=open(log_file, "w"), stderr=subprocess.STDOUT)
    sw = await asyncio.create_subprocess_exec(*[SOC_TERM, "-t", "54321"], stdin=subprocess.PIPE)
    #nw = await asyncio.create_subprocess_exec([SOC_TERM, "54320"])
    qemu = await asyncio.create_subprocess_shell("echo c | make run-only", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    nw = await asyncio.create_subprocess_exec(*[SOC_TERM, "-e", "54320"])
    await nw.communicate()

    print("Exiting")


loop = asyncio.get_event_loop()
loop.add_signal_handler(signal.SIGINT, lambda : sys.exit(-1))
loop.run_until_complete(main())
