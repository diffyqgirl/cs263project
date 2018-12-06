def bitsofbyte(byte):
  return [(byte & (1 << i)) != 0 for i in range(8)]

def isrefl(stream):
  if stream[0] is not 0xff:
    return False
  bits = bitsofbyte(stream[1])
