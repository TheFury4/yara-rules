/*
   YARA Rule Set
   Author: Emanuele Furina
   Date: 2024-05-28
   Identifier: yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_2cd9ea183ef88bc1ee850151e47ffc1613b6a4a57ddbb14ef8230cd25ba77a70 {
   meta:
      description = "yara - file 2cd9ea183ef88bc1ee850151e47ffc1613b6a4a57ddbb14ef8230cd25ba77a70.bin"
      author = "Emanuele Furina"
      date = "2024-05-28"
      hash1 = "2cd9ea183ef88bc1ee850151e47ffc1613b6a4a57ddbb14ef8230cd25ba77a70"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3>"
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c56193>"
      $s3 = "dhRh.exe" fullword wide
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s5 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s6 = "SportsBets.Properties.Resources.resources" fullword ascii
      $s7 = "SportsBets.Form1.resources" fullword ascii
      $s8 = "SportsBets.Properties" fullword ascii
      $s9 = "SportsBets.FormaNovTim.resources" fullword ascii
      $s10 = "SportsBets.Properties.Resources" fullword wide
      $s11 = "get_domasen" fullword ascii
      $s12 = "get_natprevar" fullword ascii
      $s13 = "# /pK(" fullword ascii
      $s14 = "{0} : {1} - {2} {3:0.00} - {4:0.00} - {5:0.00}" fullword wide
      $s15 = "{0}: {1} - {2} {3:0.00}" fullword wide
      $s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s17 = "oJp.JQY" fullword ascii
      $s18 = "H:\\u?(-" fullword ascii
      $s19 = "PizzaOrder.Form1.resources" fullword ascii
      $s20 = "SportsBets" fullword wide

      $op0 = { 86 18 6b 0c 06 00 34 00 68 67 }
      $op1 = { 86 18 6b 0c 1a 00 34 00 7e 67 }
      $op2 = { 02 00 05 00 c4 68 00 00 30 37 00 00 03 }
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      ( 8 of them and all of ($op*) )
}
