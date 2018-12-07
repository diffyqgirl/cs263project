import subprocess
import re
class Stream:
  def __init__(self, arr, f='', baseaddr=0, ix=0):
    self.arr = arr
    self.ix = ix
    self.filename = f
    self.baseaddr = baseaddr
    self.ixt = type(ix)
    self.killed = False
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
  def kill(self):
    self.killed = True

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
      stream.kill()
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
  return # TODO

def obj_is_refl(l):
  '*' in l

def objdump_if_refl(s):
  ob = objdump(s)
  for l in ob:
    if obj_is_refl(l):
      return ob
  return None

def get_all_cp_refls(s):
  objs = []
  while not s.killed:
    s = next_with(bin_is_call, s)
    if not s.killed:
      ob = objdump_if_refl(s)
      if ob is not None:
        objs.push((s.ix, ob))
  return objs

def extract_bytes(l):
  ll = l[8:35].split(' ')
  r = ''
  for w in ll:
    r += bytes.fromhex(w).decode('utf-8')
  return r

def get_text_segment(f):
  d = stream.baseaddr + stream.ix
  res = subprocess.run(['objdump', '-j', '.text', '-s',
                        stream.filename], stdout=subprocess.PIPE)
  out = res.stdout.decode('utf-8')
  bs = ''
  ls = out.splitlines()[4:-1]
  off = bytes.fromhex(ls[0][1:8]).decode('utf-8')
  for l in ls:
    bs += extract_bytes(l)
  return Stream(bs, f, off)

def extract_bytes(l):
  ll = l[8:35].split(' ')
  r = ''
  for w in ll:
    r += bytes.fromhex(w).decode('utf-8')
  return r

def get_text_segment(f):
   d = stream.baseaddr + stream.ix
  res = subprocess.run(['objdump', '-j', '.text', '-s',
                        stream.file], stdout=subprocess.PIPE)
  out = res.stdout.decode('utf-8')
  bs = ''
  ls = out.splitlines()[4:-1]
  off = bytes.fromhex(ls[0][1:8]).decode('utf-8')
  for l in ls:
    bs += extract_bytes(l)
  return Stream(bs, f, off)
if __name__ == "__main__":
    s = get_text_segment(argv[0])
    objs = get_all_cp_refls(s)
    for (addr, contents) in objs:
        print(hex(addr) + ": " + contents)
