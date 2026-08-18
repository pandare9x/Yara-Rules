rule ShadowHVNC_Stealer {
    meta:
        description = "Detects Shadow HVNC Stealer"
        author = "PandaRE"
        date = "2026-08-17"
        hash = "d07278643de28cdd30ff28255a1797bb"
		reference = "https://malbearlabs.com/shadow-hvnc-and-shadow-loader-the-kit-that-protects-its-license-better-than-its-customers-dd99520b6af3"

    strings:
        $s1 = "[rdp] collecting RDP connection data"
        $s2 = "[DEFENDER] no path or process specified"
		$s3 = "RXMAGIC_C2HOST"
		$s4 = "[WD] guard mode: watching PID %d"
        $s5 = "[WD-KILL] nuclear kill switch activated"
		$s6 = "[WD] WMI subscription installed"

    condition:
        uint16(0) == 0x5A4D and 4 of them
}
