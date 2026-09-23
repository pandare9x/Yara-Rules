rule PavokwiLoader {
    meta:
        description = "Detects PavokwiLoader"
        author = "PandaRE"
        date = "2026-09-22"
        hash = "009c3f6d2dd110451414783d6b04639bd99032a1838ed75f066f530296256b94"
    strings:
        $s1 = {
            48 89 5C 24 08 4C 89 44 24 18 48 89 54 24 10
            55 56 57 41 54 41 55 41 56 41 57
            48 81 EC C0 00 00 00
            81 39 03 00 00 80
            49 8B E9 4D 8B F0 4C 8B FA 48 8B F1
        }
		    $a = {
            48 89 5C 24 08 4C 89 44 24 18 48 89 54 24 10
            55 56 57 41 54 41 55 41 56 41 57
            48 81 EC ?? ?? ?? ??
            81 39 03 00 00 80
            49 8B E9 4D 8B F0 4C 8B FA 48 8B F1
        }
        $b = {
            48 8B 45 08
            48 89 44 24 68
            48 89 7C 24 60
            83 7F 0C 00
            0F 86 ?? ?? ?? ??
            44 89 6C 24 28
            48 8D 54 24 60
            4C 8B CD
            48 89 7C 24 20
            45 8B C4
            48 8D 8C 24 98 00 00 00
            E8 ?? ?? ?? ??
            0F 10 84 24 98 00 00 00
            F3 0F 7F 44 24 70
            66 0F 73 D8 08
            66 0F 7E C0
        }
		    $c = {41 C0}
    condition:
        uint16(0) == 0x5A4D and $s1 and @b > @a and @b - @a < 0x200 and #c > 50 and filesize < 5MB
}
