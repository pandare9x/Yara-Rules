rule BrokerSiphon
{
    meta:
        description = "Detects BrokerSiphon"
        author = "PandaRE"
        date = "2026-11-25"
        reference = "https://tenex.ai/blog/grand-theft-token-brokersiphon"

    strings:
        $s1  = "com/hierynomus/smbj/"
        $s2  = "jcifs/smb/SmbFile.class"
        $c1  = "/SmbXferEngine.class"
        $c2  = "/JTokenFacade.class"
        $c3  = "/TknMetadataParser.class"
        $c4  = "/SpoProbeWriteRunner.class"
        $c5  = "/JcifsCloudBridge.class"
        $c6  = "/ClientLegitimacy.class"
        $c7  = "/V2_JavaSmbCrawler.class"
        $c8  = "/JcifsOneDriveUploader.class"
        $c9  = "/WriteTestModeHandler.class"
        $c10 = "/SmbjPocTest.class"
        $c11 = "/HugeFileMultipartUploader.class"

    condition:
        uint32(0) == 0x04034B50 and filesize < 60MB and all of ($s*) and 3 of ($c*)
}
