import lldb
import binascii
from datetime import datetime
import os

def dumpToFile(file, content):
  ndx = content.rfind(",")
  content = content[:ndx] + "]}"
  f = open(file + "-0", "w")
  f.write(content)
  f.close()

def dumpToArchive(file, ndx):
  command = "cat " + file + "-0 " + "| gzip > " + file + "_" + str(ndx) + ".gz"
  os.system(command)
  command = "rm " + file + "-0"
  os.system(command)

def steploop(debugger, unused0, unused1, unused2):
  target = debugger.GetSelectedTarget()
  process = target.GetProcess()
  thread = process.GetSelectedThread()
  module = target.GetModuleAtIndex(0)

  linkTable = module.FindSection(".plt")
  tableAddress = linkTable.GetFileAddress()

  finishStart = module.FindSymbol("_fini").GetStartAddress().GetLoadAddress(target)
  finishEnd = module.FindSymbol("_fini").GetEndAddress().GetLoadAddress(target)

  text = module.FindSection(".text")

  fileIndex = 0
  stamp = str(datetime.now()).replace(' ','')

  mnem = ""
  value = ""
  triple = target.GetPlatform().GetTriple()
  replay = "{\"triple\":\""+ triple +"\",\"size\":" + str(text.GetByteSize()) + ",\"run\":[\n"
  while str(value) != "No value":
    frame = thread.GetFrameAtIndex(0)
    value = frame.FindRegister("pc")
    if str(value) != "No value":
      error = lldb.SBError()
      if(value.GetLoadAddress() >= finishStart and value.GetLoadAddress() <= finishEnd):
        break

      address = value.GetValueAsUnsigned()
      bytes = process.ReadMemory(address, 8, error)
      instr = target.GetInstructions(lldb.SBAddress(value.GetLoadAddress(), target), bytes).GetInstructionAtIndex(0)

      hexAddress = str(hex(value.GetValueAsUnsigned()))
      opcode = str(binascii.hexlify(bytes))[:instr.GetByteSize()*2]
      mnem = str(instr.GetMnemonic(target))

      #Eventually we need to compensate for non-runtime loaded dynamic libraries
      if address >= text.GetLoadAddress(target) and address <= text.GetLoadAddress(target) + text.GetByteSize():
        replay += "{\"address\":\"" + hexAddress + "\",\"opcode\":\"0x" + opcode +"\",\"mnem\":\"" + mnem +"\"},\n"
        if len(replay.splitlines()) > 48000:
          dumpToFile(stamp, replay)
          replay = "{\"triple\":\""+ triple +"\",\"size\":" + str(text.GetByteSize()) + ",\"run\":[\n"
          dumpToArchive(stamp, fileIndex)
          fileIndex += 1
      thread.StepInstruction(False)

  dumpToFile(stamp, replay)
  dumpToArchive(stamp, fileIndex)

