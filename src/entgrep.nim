import std/streams
import strutils
import math
import tables

const KEYSIZE = 48

type
  MasterKey = array[KEYSIZE, char]

func entropy(mk: MasterKey): float =
  var t = initCountTable[char]()
  for c in mk.items: t.inc(c)
  for x in t.values: result -= x/mk.len * log2(x/mk.len)

proc newMasterKey(): MasterKey =
  return result

func `$`(mk: MasterKey): string =
  for c in mk:
    result &= ord(c).toHex[14..15]

proc extractKey(s: Stream, threshold: float): MasterKey =
  let startAddr = s.getPosition
  let bytesRead = s.peekData(addr result, KEYSIZE)
  if result.entropy > threshold and bytesRead == KEYSIZE:
    discard s.readData(addr result, KEYSIZE)
    if ord(s.peekChar) == 0:
      echo "Possible key found at: 0x" & startAddr.toHex
      echo "Entropy: " & $result.entropy
      echo $result
      echo "====================================================="
      return result
    return newMasterKey()

proc processFile(fn: string, blobSize=48, threshold=5.2) =
  var 
    strm = newFileStream(fn, fmRead)
    prev, cur: char

  while not strm.atEnd():
    prev = strm.readChar
    cur = strm.peekChar
    if ord(prev) == 0 and ord(cur) != 0:
      var mk = extractKey(strm, threshold)

  strm.close()


when isMainModule:
  import cligen
  dispatch(
    processFile, 
    cmdName="entgrep", 
    doc="a grep for secret stuff", 
    short={
      "fn": 'f',
      "blobSize": 's',
      "threshold": 't'
    }
  )
  # processFile(r"C:\Temp\image_7988.dmp")
