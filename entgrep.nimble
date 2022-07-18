# Package

version       = "0.2.0"
author        = "srozb"
description   = "Grep but for secrets"
license       = "MIT"
srcDir        = "src"
bin           = @["entgrep"]


# Dependencies

requires "nim >= 1.6.6, cligen >= 1.5.24"
