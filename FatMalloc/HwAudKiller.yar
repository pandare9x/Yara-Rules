rule win_mal_HwAudKiller {
    meta:
        author = "RussianPanda"
        description = "Detects HwAudKiller BYOVD AV/EDR killer "
        date = "3/16/2025"
		hash = "28278b8c85c832417f9860fe8ea3ddbb9ff1d5860317db4813227a3a52b7c7cc"
    strings:
        $s1 = "[+] Havoc Process Terminator"
        $s2 = "sc create Havoc"
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}

