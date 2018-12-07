import subprocess
import re
class Stream:
  def __init__(self, arr, file='', baseaddr=0, ix=0):
    self.arr = arr
    self.ix = ix
    self.file = file
    self.baseaddr = baseaddr
    self.ixt = type ix
  def __add__(self, ix):
    return Stream(self.arr, ix + self.ix)
  def __sub__(self, ix):
    return Stream(self.arr, ix - self.ix)
  def __iadd__(self,ix):
    self.ix += ix
    return self
  def __isub__(self, ix):
    self.ix -= ix
    return self
  def __iter__(self):
    return self
  def __next__(self):
    oix = self.ix
    self.ix += 1
    return self.arr[oix]
  def __getitem__(self, ix):
    if isinstance(ix, self.ixt):
      return self.arr[ix]
    else:
      return self.arr[slice(self.ix + ix.start if ix.start else None, 
                            self.ix + ix.stop if ix.stop else None,
                            ix.step)]
  

def bin_is_refl(stream):
  """Checks if the stream begins with a reflector gadget opcode"""
  if stream[0] is not 0xff:
    return False
  bits = stream[1] & 0b00_111_000
  return (bits >= 0b00_010_000) and (bits <= 0b00_101_000)

def bin_is_call(stream):
  """Checks if the stream begins with a call of any type (for finding call-preceded gadgets)"""
  if stream[0] is 0xe8:
    return True
  elif stream[1] is 0xff:
    bits = stream[1] & 0b00_111_000
    return (bits >= 0b00_010_000) and (bits <= 0b00_011_000)
  else:
    return False

def next_with(p,stream):
  """
  Finds the next stream location with property p; 
  note: if the current satisfies p, it is ignored.
  """
  b = False
  while not b:
    try:
      b = p(stream)
    except IndexError:
      return stream
    stream += 1
  return stream

def last_with(p, stream):
  """
  Finds the last stream location with property p; 
  note: if the current satisfies p, it is ignored.
  """
  b = False
  while not b:
    try:
      b = p(stream)
    except IndexError:
      return stream
    stream -= 1
  return stream

def objdump_string(stream):
  d = stream.baseaddr + stream.ix
  res = subprocess.run(['objdump', '-d', 
                        '--start-address=' + str(d), 
                        '--stop-address=' + str(d + 0x40),
                        stream.file], stdout=subprocess.PIPE)
  return res.stdout.decode('utf-8')

def objdump(s):
  string = objdump_string(s)
  ls = string.splitlines()
  return ls

def obj_extract(l):
  r = re.compile("(?P<addr>.+):(?:\s+[0-9a-f]{2})+\s+(?P<instr>.+)")
  return

def obj_is_refl(l):
  '*' in l

def objdump_if_refl(s):
  ob = objdump(s)
  for l in ob:
    if obj_is_refl(l):
      return ob
  return None
