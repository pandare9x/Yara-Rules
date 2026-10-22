rule win_acrstealer
{
    meta:
        author = "PandaRE"
        description = "ACRStealer infostealer"
        date = "2026-10-22"
        hash = "9530cd1c1f44affa2df3ecabf987a489d1f1955faf39af345ee97a7fe4419d5a"

    strings:
        $hash_b = {
            B8 75 65 73 70
            33 44 24 0C
            89 C1
            C1 E9 1E
        }

        $hash_mul = {
            BA B9 E5 E4 1C
            [0-4]
            F7 E2
            69 C? 6D 47 58 BF
        }

        $hash_f = {81 C6 44 81 70 75}

        $spltmix1 = {15 7C 4A 7F 81 D? B9 79 37 9E}

        $spltmix_dd = {BA 95 0A 22 27 [0-4] F7 E?}

        $dec = {
            55 53 57 56
            [0-8]
            E8
        }

        $xrsft = {C1 E? 0B [0-16] C1 E? 05}

    condition:
        uint16(0) == 0x5A4D
        and $hash_b
        and $hash_mul
        and 2 of ($spltmix1, $spltmix_dd, $xrsft)
        and ($hash_f or $dec)
}
