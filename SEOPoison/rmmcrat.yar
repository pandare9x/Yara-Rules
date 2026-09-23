rule RMMCRAT {
    meta:
        description = "Detects RMMCRAT"
        author = "PandaRE"
        date = "2026-09-22"
        hash = "3afabe2f9197f66460044083c708a5206291b2efe1138be1c763f60c47069787"
    strings:
        $s1 = "RMMC"
		$s2 = "RMM Agent embedded configuration"
    condition:
        uint16(0) == 0x5A4D and all of them
}