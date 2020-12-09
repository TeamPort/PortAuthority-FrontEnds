def setup(debugger, unused0, unused1, unused2):
  target = debugger.GetSelectedTarget()
  process = target.GetProcess()

  target.BreakpointCreateByName('main')
