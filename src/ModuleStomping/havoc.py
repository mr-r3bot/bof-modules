from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists


class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L".self.size) + self.buffer

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s) + 1, s)
        self.size += calcsize(fmt)

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4

def bof(demon_id, *args):
    task_id = None
    demon: Demon = None
    packer: Packer = Packer()
    string: str = None
    int32: int = 0

    # get the agent based on Demon ID
    demon = Demon(demon_id)
    # Check if enough arguments have been specified
    if len(args) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    # Get passed arguments
    string = args[0]
    int32 = int(args[1])

    # Add the arguments to the packer
    packer.addstr(string)
    packer.addint(int32)

    task_id = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked the demon to execute the example bof")

    # Task the agent to execute the bof with the entry point being "go"
    # and the arguments being the packed arguments buffer
    # change path to bof.o
    demon.InlineExecute(task_id, "go", "bof.o", packer.getbuffer(), False)
    return task_id

RegisterCommand(bof, "", "Example bof command", 0, "[string] [32-bit integer]", "Quang Vo 55555")