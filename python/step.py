import lldb
import binascii
from datetime import datetime

def steploop(debugger, unused0, unused1, unused2):
  target = debugger.GetSelectedTarget()
  process = target.GetProcess()
  thread = process.GetSelectedThread()
  module = target.GetModuleAtIndex(0)

  linkTable = module.FindSection(".plt")
  tableAddress = linkTable.GetFileAddress()

  finishStart = module.FindSymbol("_fini").GetStartAddress().GetLoadAddress(target)
  finishEnd = module.FindSymbol("_fini").GetEndAddress().GetLoadAddress(target)

  mnem = ""
  value = ""
  triple = target.GetPlatform().GetTriple()
  replay = "{\"triple\":\""+ triple +"\",\"size\":" + str(module.FindSection(".text").GetByteSize()) + ",\"run\":["
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
      replay += "{\"address\":\"" + hexAddress + "\",\"opcode\":\"0x" + opcode +"\",\"mnem\":\"" + mnem +"\"},"
      if (address >= tableAddress) and (address <= tableAddress + linkTable.GetByteSize()):
        thread.StepOut()
      else:
        thread.StepInstruction(False)

  ndx = replay.rfind(",")
  replay = replay[:ndx] + "]}"
  f = open(str(datetime.now()).replace(' ',''), "w")
  f.write(replay)
  f.close()
