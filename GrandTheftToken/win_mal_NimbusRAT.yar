rule win_mal_NimbusRAT
{
    meta:
        description = "Detects Nimbus RAT > October 2026 builds"
        author = "PandaRE"
        date = "2026-11-25"
        reference = "https://tenex.ai/blog/grand-theft-token-brokersiphon"

    strings:
        $s1 = {63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 70 69 2F 73 65 72 76 69 63 65 73 2F 64 72 69 76 65 2F}
        $s2 = {63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 75 74 68 2F 6F 61 75 74 68 32 2F 53 65 72 76 69 63 65 41 63 63 6F 75 6E 74 43 72 65 64 65 6E 74 69 61 6C 73}
        $c1 = {2F 4D 65 6D 6F 72 79 43 6C 61 73 73 4C 6F 61 64 65 72 2E 63 6C 61 73 73}
        $c2 = {2F 4A 61 76 61 53 6F 75 72 63 65 46 72 6F 6D 53 74 72 69 6E 67 2E 63 6C 61 73 73}
        $c3 = {2F 4A 61 76 61 43 6C 61 73 73 4F 62 6A 65 63 74 2E 63 6C 61 73 73}
        $c4 = {2F 44 72 69 76 65 46 61 63 74 6F 72 79 2E 63 6C 61 73 73}
        $c5 = {2F 52 65 74 72 79 65 72 24 52 65 74 72 69 61 62 6C 65 52 75 6E 6E 61 62 6C 65 2E 63 6C 61 73 73}
        $c6 = {77 65 62 72 74 63 2D 6A 61 76 61 2D 77 69 6E 64 6F 77 73 2D 78 38 36 5F 36 34 2E 64 6C 6C}

    condition:
        uint32(0) == 0x04034B50 and filesize < 60MB and all of ($s*) and 3 of ($c*)
}
