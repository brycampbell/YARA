/*
   Yara Rule Set
   Author: Bryan Campbell
   Date: 2018-04-01
   Identifier: YARA - pp
   Reference: https://github.com/brycampbell/Yara
   Reference: https://www.proofpoint.com/us/threat-insight/post/unraveling-ThreadKit-new-document-exploit-builder-distribute-The-Trick-Formbook-Loki-Bot-malware
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_53e8890f0d002d9611675419b3d8d0899b599c59f4557e105211d294bf92f023 {
   meta:
      description = "YARA - pp - file 53e8890f0d002d9611675419b3d8d0899b599c59f4557e105211d294bf92f023"
      author = "Bryan Campbell"
      reference = "https://github.com/brycampbell/Yara"
      date = "2018-04-01"
      hash1 = "53e8890f0d002d9611675419b3d8d0899b599c59f4557e105211d294bf92f023"
   strings:
      $s1 = "\\objdata \\mmath\\bin-000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
      $s2 = "%tMp%\\inteldriverupd1.sct" fullword wide
      $s3 = "{\\field{\\*\\fldinst{INCLUDEPICTURE \"http://truckingload.org/newbuild/t.php?stats=send&thread=0\" MERGEFORMAT \\\\d \\\\w0001 " ascii
      $s4 = "{\\rt{\\pict\\jpegblip\\picw24\\pich24\\bin49922 " fullword ascii
      $s5 = "\\objdata \\mmath\\bin-000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
      $s6 = "\\object\\objhtml\\objupdate\\v" fullword ascii
      $s7 = "\\object\\objemb\\objupdate\\v" fullword ascii
      $s8 = "\\objdata 0105000002000000080000005061636b6167650000000000000000003101000002007461736b2e62617400433a5c496e74656c5c7461736b2e6261" ascii
      $s9 = "\\objdata 0105000002000000080000005061636b616765000000000000000000a50200000200696e74656c647269766572757064312e73637400433a5c496e" ascii
      $s10 = "\\objdata 0105000002000000080000005061636b616765000000000000000000717f000002006465636f792e646f6300433a5c496e74656c5c6465636f792e" ascii
      $s11 = "\\objdata 0105000002000000080000005061636b616765000000000000000000810900000200326e642e62617400433a5c496e74656c5c326e642e62617400" ascii
      $s12 = "\\bin2633" fullword ascii
      $s13 = "}numbernfigureversionhigh" fullword ascii
      $s14 = "\\objdata 0105000002000000080000005061636b61676500000000000000000092ae080002006578652e65786500433a5c496e74656c5c6578652e65786500" ascii
      $s15 = "\\objdata \\mmath" fullword ascii
      $s16 = "\\object\\objhtml\\v" fullword ascii
   condition:
      ( uint16(0) == 0x5c7b and
        filesize < 4000KB and
        ( 8 of them )
      ) or ( all of them )
}
