import std/streams
import strutils
import math
import tables

proc entropy(s: string): float {.inline.} =
  var t = initCountTable[char]()
  for c in s: t.inc(c)
  for x in t.values: result -= x/s.len * log2(x/s.len)

func hexlify(buf: string): string =  # TODO: hexlify it easier
  for c in buf:
    result &= ord(c).toHex[14..15]

proc reportFinding(offset: Natural, blob: string, asJson: bool) =
  if asJson:
    echo "{\"offset\": \"0x" & offset.toHex & "\", \"entropy\": " & $blob.entropy & ", \"blob\": \"" & blob.hexlify & "\"}"
  else:
    echo "High entropy blob found at: 0x" & offset.toHex & ", Entropy: " & $blob.entropy
    echo blob.hexlify
    echo "====================================================="

proc extractBlob(blobSize: Natural, s: Stream, threshold: float, asJson: bool): string {.inline.} =
  let
    blob = s.peekStr(blobSize)  # TODO: use var blob from heap
    trailingChar = s.peekStr(blobSize+1)[blobSize]  # TODO: optimize
  if blob.entropy > threshold and trailingChar == '\0':
    discard s.readStr(blobSize)
    return blob

proc processFile(fn: string, blobSize=48, threshold=5.2, asJson=false) =
  var 
    strm = newFileStream(fn, fmRead)
    prev, cur: char
    blob = newStringOfCap(blobSize)

  while not strm.atEnd():
    prev = strm.readChar
    cur = strm.peekChar
    if ord(prev) == 0 and ord(cur) != 0:
      let offset = strm.getPosition
      blob = extractBlob(blobSize, strm, threshold, asJson)
      if blob == "":
        continue
      reportFinding(offset, blob, asJson)

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
      "threshold": 't',
      "asJson": 'j'
    }
  )
  # processFile(r"C:\Temp\image_7988.dmp")
