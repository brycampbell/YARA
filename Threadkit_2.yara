
rule sig_8e1c6f44b02e72b1c1c9af0ffdcee0fbe67fb8ee370bc67e4e01ec43f8b92ec9 {
   meta:
      description = "YARA - pp - file 8e1c6f44b02e72b1c1c9af0ffdcee0fbe67fb8ee370bc67e4e01ec43f8b92ec9.bin"
      author = "Bryan Campbell"
      reference = "https://github.com/brycampbell/Yara"
      date = "2018-04-01"
      hash1 = "8e1c6f44b02e72b1c1c9af0ffdcee0fbe67fb8ee370bc67e4e01ec43f8b92ec9"
   strings:
      $x1 = "ftp://anonymous:anypass@5.149.252.158/template555.hta" fullword wide
      $x2 = "C:\\Memtest86\\lkup\\Preview\\HttpHead.pdb" fullword ascii
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
      $s4 = "{ INCLUDEPICTURE \"http://5.149.252.158/uag.php\" \\\\*MERGEFORMAT\\\\d}" fullword ascii
      $s5 = "Electrnic.exe" fullword wide
      $s6 = "ImmGetCompositionString returned: %d, %p" fullword ascii
      $s7 = "TEMP=%TEMP%" fullword ascii
      $s8 = "templateSebastian Predesktop MuseEvent ONR " fullword ascii
      $s9 = "operator co_await" fullword ascii
      $s10 = "GetOpenFileName returned Error #" fullword ascii
      $s11 = "version=\"5.0.0.0\"" fullword ascii
      $s12 = "\\*\\objdata \\bin0\\bin00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
      $s13 = "\\object\\objhtml\\objupdate" fullword ascii
      $s14 = "Can't Get VIDEOStream Info" fullword ascii
      $s15 = "!iTXtXML:com.adobe.xmp" fullword ascii
      $s16 = "ImmSetCompositionString returned: %d" fullword ascii
      $s17 = "picture file (*.jpg, *.bmp)" fullword ascii
      $s18 = "PATH=%PATH%" fullword ascii
      $s19 = "Playing %s format" fullword ascii
   condition:
      ( uint16(0) == 0x5c7b and
        filesize < 800KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
