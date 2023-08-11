import "pe"
import "math"

//Important
//This module is not built into YARA by default, to learn how to include it refer to Compiling and installing YARA. Bad news for Windows users: this module is not supported on Windows.
//https://yara.readthedocs.io/en/stable/modules/magic.html
//import "magic"

rule signed
{
    condition:
          pe.is_signed
}

rule not_signed
{
    condition:
          not pe.is_signed and ( filesize < 10KB )
}

//rule encrypted_payload {
//  condition:
//        magic.mime_type() == "application/octet-stream" and
//        math.entropy(0, filesize) > 7.5 and
//        filesize < 300KB
//}

rule encrypted_payload {
  condition:
        math.entropy(0, filesize) > 7.5 and
        filesize < 300KB
}