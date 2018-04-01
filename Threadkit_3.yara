
rule sig_2bb9d0d8166a8d330cb3c5be6fb60539fe29e05cc3acb4ac7ec3da233fb013ec {
   meta:
      description = "YARA - pp - file 2bb9d0d8166a8d330cb3c5be6fb60539fe29e05cc3acb4ac7ec3da233fb013ec"
      author = "Bryan Campbell"
      reference = "https://github.com/brycampbell/Yara"
      date = "2018-04-01"
      hash1 = "2bb9d0d8166a8d330cb3c5be6fb60539fe29e05cc3acb4ac7ec3da233fb013ec"
   strings:
      $s1 = "C:\\Restricts\\artisan\\abbr.pdb" fullword ascii
      $s2 = "http://www.strongene.com" fullword wide
      $s3 = "http://190.97.165.202/t.php?thread=thread1&t=h" fullword wide
      $s4 = "errorLog grouping " fullword ascii
      $s5 = "{\\field{\\*\\fldinst{INCLUDEPICTURE \"http://190.97.165.202/t.php?stats=send&thread=thread1\" MERGEFORMAT \\\\d \\\\w0001 \\\\h" ascii
      $s6 = "wsdl=http://190.97.165.202/t.php" fullword wide
      $s7 = "DDDDDDE" fullword ascii /* reversed goodware string 'EDDDDDD' */
      $s8 = "<description>Extra files</description>" fullword ascii
      $s9 = "wwwwwwq=DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDCgwwwwwwdDD" fullword ascii
      $s10 = "Cwwwwwwq=DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDCgwwwwwww" fullword ascii
      $s11 = "333333333333333333333333333333333333333333333333333333=D7wwwwwdM" fullword ascii
      $s12 = "\\*\\objdata \\bin00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
      $s13 = "\\bin0\\bin000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
      $s14 = "\\bin0\\bin000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ascii
   condition:
      ( uint16(0) == 0x5c7b and
        filesize < 3000KB and
        ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
