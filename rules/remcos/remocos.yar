/*
   YARA Rule Set
   Author: Emanuele Furina
   Date: 2024-05-28
   Identifier: yara
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_3ab523766f4c1b69be83287f94b0a761b6d65e5723b2e554322dc99b94f1ec56 {
   meta:
      description = "yara - file 3ab523766f4c1b69be83287f94b0a761b6d65e5723b2e554322dc99b94f1ec56.bin"
      author = "Emanuele Furina"
      date = "2024-05-28"
      hash1 = "3ab523766f4c1b69be83287f94b0a761b6d65e5723b2e554322dc99b94f1ec56"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System >
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System >
      $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide
      $s5 = "[+] ShellExec success" fullword ascii
      $s6 = "[+] before ShellExec" fullword ascii
      $s7 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii
      $s8 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii
      $s9 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s10 = "rmclient.exe" fullword wide
      $s11 = "Keylogger initialization failure: error " fullword ascii
      $s12 = "[-] CoGetObject FAILURE" fullword ascii
      $s13 = "Online Keylogger Started" fullword ascii
      $s14 = "Online Keylogger Stopped" fullword ascii
      $s15 = "Offline Keylogger Started" fullword ascii
      $s16 = "Offline Keylogger Stopped" fullword ascii
      $s17 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide
      $s18 = "Executing file: " fullword ascii
      $s19 = "\\logins.json" fullword ascii
      $s20 = "[Firefox StoredLogins Cleared!]" fullword ascii

      $op0 = { 51 ff 34 24 e8 9c 0f 00 00 8b c1 59 c3 68 1c 5e }
      $op1 = { 85 f6 5f 0f 95 c0 5e c2 08 00 e8 4c ff ff ff cc }
      $op2 = { 53 8b 5c 24 10 55 53 e8 95 f4 ff ff ff 74 24 18 }
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( 1 of ($x*) and 4 of them and all of ($op*) )
}
