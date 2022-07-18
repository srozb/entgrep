import std/streams
import strutils
import strformat
import math
import tables


proc entropy(s: string): float {.inline.} =
  var t = initCountTable[char]()
  for c in s: t.inc(c)
  for x in t.values: result -= x/s.len * log2(x/s.len)

func hexlify(buf: string): string =  # TODO: hexlify it easier
  for c in buf:
    result &= ord(c).toHex[14..15]

proc reportFinding(offset: Natural, blob: string, asJson: bool, fn: string) =
  if asJson:
    echo "{\"fn\": \"" & fn & "\", " & "\"offset\": \"0x" & offset.toHex & "\", \"entropy\": " & $blob.entropy & ", \"blob\": \"" & blob.hexlify & "\"}"
  else:
    echo fmt"{fn},0x{offset}: (e:{$blob.entropy}) {blob.hexlify}"

proc extractBlob(blob: var string, blobSize: Natural, s: Stream, threshold: float, asJson: bool) {.inline.} =
  blob = s.peekStr(blobSize)
  try:
    let trailingChar = s.peekStr(blobSize+1)[blobSize]  # TODO: optimize
    if blob.entropy >= threshold and trailingChar == '\0':
      discard s.readStr(blobSize)
    else:
      blob = ""
  except IndexDefect:  # End of file reached.
    blob = ""
    return

proc processStream(strm: Stream, blobSize=48, threshold=5.2, asJson=false, fn: string) =
  var 
    prev, cur: char
    blob = newStringOfCap(blobSize)

  while not strm.atEnd():
    prev = strm.readChar
    cur = strm.peekChar
    if ord(prev) == 0 and ord(cur) != 0:
      let offset = strm.getPosition
      blob.extractBlob(blobSize, strm, threshold, asJson)
      if blob == "":
        continue
      reportFinding(offset, blob, asJson, fn)

proc processFiles(blobSize: Natural=48, threshold=5.2, asJson=false, files: seq[string]) =
  if 0 >= threshold or threshold >= 8:
    echo "Threshold must fit between 0 and 8."
    return
  for fn in files.items:
    echo "Processing " & fn & "..."
    var strm = newFileStream(fn, fmRead)
    try:
      processStream(strm, blobSize, threshold, asJson, fn)
    finally:
      strm.close()

when isMainModule:
  import cligen
  dispatch(
    processFiles, 
    cmdName="entgrep", 
    doc="A grep for secret stuff", 
    short={
      "blobSize": 's',
      "threshold": 't',
      "asJson": 'j'
    }
  )
