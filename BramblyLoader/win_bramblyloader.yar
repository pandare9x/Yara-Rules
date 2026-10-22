rule win_brambly_loader
{
    meta:
        author = "PandaRE"
        description = "Brambly loader"
        date = "2026-10-18"
        hash = "ca4717d84adc33c42fed4bd9f4656893a2f8892b943b250f5265cb6303b64371"

    strings:
        $a1 = {
            BA 62 6A 6C 6C
            [0-8]
            0F B6 ??
            6B D2 1F
            4?
            83 C? 20
       }

        $b1 = {81 FA 6C 1A A7 91}
        $b2 = {81 FA 46 5C 31 E8}
        $b3 = {81 FA EF 2B DD 68}
        $b4 = {81 FA 55 5C 7B 1D}
        $b5 = {81 FA 4E D9 0C 35}
        $b6 = {81 FA 19 D2 D7 3D}
        $b7 = {81 FA AA E1 F0 13}

        $c1 = {
            83 E? 7F
            8A 4C ?? 08
            30 [2]
            4?
       }

        $d1 = {83 ED 01 73 07 0F B6 ?? 4? 6A 07 5D}

        $e1 = {64 A1 18 00 00 00 [0-16] 8B 40 30}
        $e2 = {8B 4? 3C 8B 44 ?? 78}
        $e3 = {C7 40 04 6C 2E 64 6C C7 00 6E 74 64 6C}
        $e4 = {
            66 C7 44 24 ?? 4C 64
            C6 44 24 ?? 72
            66 C7 44 24 ?? 70 48
       }
        $e5 = {
            8B ?? A4 00 00 00
            C1 E? 08
            [0-8]
            66 81 FA 03 06
       }
        $e6 = {6A 00 6A 01 FF 74 24 ?? FF D?}
        $e7 = {59 5A 51 52 55 53 57 56 81 EC}

    condition:
        $a1
        and 3 of ($b*)
        and $c1
        and $d1
        and 2 of ($e*)
}
