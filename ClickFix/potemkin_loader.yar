rule PotemkinLoader {
    meta:
        author = "RussianPanda"
        description = "Detects Potemkin Loader"
        date = "6/4/2026"
        hash = "2abe5dd3a057fdef935722e50e9251c272d29fd26113187b853a1f9a9cb89d9b"
    strings:
        $s1 = "[Agent] DLL returned (updatedll), reloading..." ascii
        $s2 = "dll_debug.log" ascii
        $s3 = "[Agent] LoadAndRunDLL=" ascii
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}
