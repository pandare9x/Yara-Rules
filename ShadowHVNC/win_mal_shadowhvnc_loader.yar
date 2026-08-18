rule ShadowHVNC_Loader {
    meta:
        description = "Detects Shadow HVNC Loader"
        author = "PandaRE"
        date = "2026-08-17"
		referenced = "https://malbearlabs.com/shadow-hvnc-and-shadow-loader-the-kit-that-protects-its-license-better-than-its-customers-dd99520b6af3"

    strings:
        $s1 = "Local\\BridgeAgent"
        $s2 = "windows_clipboard_failed"
		$s3 = "/api/agent/connect"
		$s4 = "binding Backstage worker to private desktop"

    condition:
        uint16(0) == 0x5A4D and 3 of them
}
