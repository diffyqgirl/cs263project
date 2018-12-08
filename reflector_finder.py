import subprocess
import re
import sys

call_only = True

class Stream:
  def __init__(self, arr, f='', baseaddr=0, ix=0):
    self.arr = arr
    self.ix = ix
    self.filename = f
    self.baseaddr = baseaddr
    self.ixt = type(ix)
    self.killed = False
  def __add__(self, ix):
    return Stream(self.arr, self.filename, self.baseaddr, ix + self.ix)
  def __sub__(self, ix):
    return Stream(self.arr, self.filename, self.baseaddr, ix - self.ix)
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
      try:
        return self.arr[self.ix + ix]
      except IndexError:
        self.kill()
        raise IndexError
    else:
      try:
        return self.arr[slice(self.ix + ix.start if ix.start else None, 
                            self.ix + ix.stop if ix.stop else None,
                            ix.step)]
      except IndexError:
        self.kill()
        raise IndexError
  def kill(self):
    self.killed = True

def bin_is_refl(stream):
  """Checks if the stream begins with a reflector gadget opcode"""
  if stream[0] != 0xff:
    return False
  bits = stream[1] & 0b00_111_000
  return (bits >= 0b00_010_000) and (bits <= 0b00_101_000)

def bin_is_call(stream):
  """Checks if the stream begins with a call of any type (for finding call-preceded gadgets)"""
  # print(chr(stream[0]) + chr(stream[1]))
  if stream[0] == 0xe8:
    return True
  elif stream[0] == 0x9a:
    return True
  elif stream[1] == 0xff:
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
    stream += 1
    try:
      b = p(stream)
    except IndexError:
      stream.kill()
      return stream
  return stream

def last_with(p, stream):
  """
  Finds the last stream location with property p; 
  note: if the current satisfies p, it is ignored.
  """
  b = False
  while not b:
    stream -= 1
    try:
      b = p(stream)
    except IndexError:
      stream.kill()
      return stream
  return stream

def objdump_string(stream):
  d = stream.baseaddr + stream.ix
  # print(str(d))
  res = subprocess.run(['objdump', '-d', 
                        '--start-address=' + str(d), 
                        '--stop-address=' + str(d + 0x20),
                        stream.filename], stdout=subprocess.PIPE)
  return res.stdout.decode('utf-8')

def objdump(s, doprint=False):
  string = objdump_string(s)
  if doprint:
    print(string)
  ls = string.splitlines()[6:-1]
  return ls

def obj_extract(l):
  r = re.compile("(?P<addr>.+):(?:\s+[0-9a-f]{2})+\s+(?P<instr>.+)")
  return # TODO (currently dead code)

def obj_is_refl(l):
  return '*' in l

def obj_is_ret(l):
  return 'ret' in l

def objdump_if_refl(s, t=False):
  ob = objdump(s,t)
  b = False
  for l in ob:
    b = b or obj_is_refl(l)
    if obj_is_ret(l):
      return ob if b else None
  return None

def get_all_cp_refls(s):
  objs = []
  b = True
  f = bin_is_call if call_only else bin_is_refl
  while not s.killed:
    s = next_with(f, s)
    if not s.killed:
      ob = objdump_if_refl(s)
      if ob is not None:
        objs += [(s.ix, ob)]
    b = False
  return objs

def get_text_segment(f):
  res = subprocess.run(['objdump', '-j', '.text', '-s',
                        f], stdout=subprocess.PIPE)
  out = res.stdout.decode('ascii')
  bs = b''
  ls = out.splitlines()[4:-1]
  off = int(ls[0][1:8], 16)
  # print(off)
  for l in ls:
    bs += extract_bytes(l)
  return Stream(bs, f, off)

def extract_bytes(l):
  ll = l[8:44].split(' ')
  r = b''
  for w in ll:
    r += bytes.fromhex(w)
  return r

if __name__ == "__main__":
    s = get_text_segment(sys.argv[1])
    objs = get_all_cp_refls(s)
    for (addr, contents) in objs:
        print(('0x%8x' % addr) + ":\n--------\n" + '\n'.join(contents))
