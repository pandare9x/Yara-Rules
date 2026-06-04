rule RMMProject {
    meta:
        author = "RussianPanda"
        description = "Detects RMMProject RAT"
        date = "6/4/2026"
        hash = "3b7ae925e2d64522b4f69b56285b05aeca8c5aab5ab46a9c02c4fafb69d881ce "
    strings:
        $s1 = "[RTSC] OpenInputSocket: sending session_id=" ascii
        $s2 = "kCookies: total_cookies=" ascii
        $s3 = "GetChromiumKey" ascii
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}
