rule BeigeBurrow {
    meta:
        description = "Detects BeigeBurrow Reverse Tunnel Agent"
        author = "RussianPanda"
        date = "2026-04-17"
        hash = "a2b6c7a9c4490df70de3cdbfa5fc801a3e1cf6a872749259487e354de2876b7c"

    strings:
        $s1 = "connection failed: %v, retrying in 5m"
        $s2 = "failed to dial %s: %v"
		$s3 = "failed to read target: %v"

    condition:
        uint16(0) == 0x5A4D and all of them
}
