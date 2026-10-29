import "dotnet"

rule PureCrypter 
{
    meta:
        author = "RussianPanda"
        date = "2024-01-09"
        modified = "2026-10-19"
        reference = "https://www.zscaler.com/blogs/security-research/technical-analysis-purecrypter"
        description = "Detects PureCrypter"
        hash = "566d8749e166436792dfcbb5e5514f18c9afc0e1314833ac2e3d86f37ff2030f"

    strings:
        $s1 = {28 ?? 00 00 ?? 28 02 00 00 2B 28 ?? 00 00 (0A|06)}
        $s2 = {73 ?? 00 00 0A}
        $s3 = {73 ?? 00 00 06 6F ?? 00 00 06}
        $s4 = {52 65 73 6F 75 72 63 65 4D 61 6E 61 67 65 72}
        $s5 = {28 ?? 00 00 ?? 6F ?? 00 00 0A 28 03 00 00 2B ?? 6F ?? 00 00 0A 28 ?? 00 00 2B} 
        
        $fp1 = "Input does not match expected format: [x-y]."
    condition:
        filesize < 6MB and
        4 of ($s*) and dotnet.number_of_resources == 1 and dotnet.resources[0].length > 300KB and
        not 1 of ($fp*)
}
