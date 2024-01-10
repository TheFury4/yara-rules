import "pe"

rule CheatVanta-Fivem 
{
    meta:
        author = "Emanuele Furina"
        date = "2024-01-10"
        description = "Detects the injector of the fivem cheat Vanta"
    strings:
        $str0 = "Drag vanta into injector!"
        $str1 = "https://vantacheats.rip/"
        $str2 = "vanta.dll"
    condition:
        uint16(0) == 0x5a4d and
        any of them
}
