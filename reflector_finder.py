def bits_of_byte(byte):
  """Coerce a byte into a [Bit] format, where Bit = Bool"""
  return [(byte & (1 << i)) != 0 for i in range(8)]

class Stream:
  def __init__(self, arr, ix=0):
    self.arr = arr
    self.ix = ix
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
  

def is_refl(stream):
  """Checks if the stream begins with a reflector gadget opcode"""
  if stream[0] is not 0xff:
    return False
  bits = stream[1]
  return (bits >= 0b00_010_000) and (bits <= 0b11_101_111)

def is_call(stream):
  """Checks if the stream begins with a call of any type (for finding call-preceded ones)"""
  if stream[0] is 0xe8:
    return True
  elif stream[1] is 0xff:
    bits = stream[1]
    return (bits >= 0b00_010_000) and (bits <= 0b11_011_111)
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
