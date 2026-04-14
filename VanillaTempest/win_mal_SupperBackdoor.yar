rule SupperBackdoor {
    meta:
        description = "Detects Supper backdoor"
        author = "RussianPanda"
        date = "2026-04-14"
        hash = "bf2ba1f30ef8ca6f9946f6ec21118eff3c3442590bbedea150e2d670e78ab986"
    strings:
        $s1 = "schtasks.exe /Create /SC MINUTE /TN GoogleUpdateTask"
		$s2 = "serv disconnect"
		$s3 = "fail run cmd"
		$s4 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000"
    condition:
        3 of them
}
