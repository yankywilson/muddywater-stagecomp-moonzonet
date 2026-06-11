import "pe"
import "hash"

rule MuddyWater_Stagecomp_Downloader
{
    meta:
        description   = "MuddyWater 'Stagecomp' first-stage downloader (moonzonet.com C2)"
        author        = "Yanky Wilson (github.com/yankywilson)"
        date          = "2026-06-11"
        version       = "1.0"
        tlp           = "TLP:CLEAR"
        malware       = "Stagecomp downloader (native C++ WinHTTP courier)"
        actor         = "MuddyWater (Iran/MOIS) - MODERATE confidence; see assessment"
        reference     = "Rapid7, 'Muddying the Tracks', May 2026"
        hash_sha256   = "a92d28f1d32e3a9ab7c3691f8bfca8f7586bb0666adbba47eab3e1a8faf7ecc0"
        hash_sha1     = "0ba2306ec15f7124fafc7615e81f34c7986ba9a5"
        hash_md5      = "7f3c8a7fe78d3d05b6022df3ea0c15fb"
        imphash       = "9963ebabcee092908eac2414f7c4661a"
        note          = "String encoding is mixed: WinHTTP URL/UA strings are UTF-16 (wide); JSON beacon bodies are ASCII. Modifiers below reflect that."

    strings:
        // --- C2 agent + host (UTF-16 LPCWSTR as built for WinHTTP) ---
        $ua    = "StageClient/2.0" wide          // anchor on the SUBSTRING; runtime header is exactly "User-Agent: StageClient/2.0"
        $host  = "moonzonet.com" wide

        // --- URI chain (wide) ---
        $u_reg = "/register" wide
        $u_chk = "/check" wide
        $u_sta = "/status" wide
        $u_d1  = "/download/Game.dll" wide
        $u_d2  = "/download/Game.exe" wide
        $u_d3  = "/download/Game.config" wide

        // --- JSON beacon templates (ASCII .rdata) ---
        $j_reg = "{\"client_id\":\"%s\",\"computer_name\":\"%s\",\"username\":\"%s\",\"domain\":\"%s\"}" ascii
        $j_sta = "{\"client_id\":\"%s\",\"status\":\"%s\",\"error_code\":\"%s\"}" ascii

        // --- gate verdict tokens (BOTH are GO-signals; loop occurs only on absence of either) ---
        $g_app1 = "\"approved\":true" ascii
        $g_app2 = "\"approved\": true" ascii
        $g_ret1 = "\"retry\":true" ascii
        $g_ret2 = "\"retry\": true" ascii

        // --- drop / staging artifacts (ASCII) ---
        $d_dll  = "WebView2Loader.dll" ascii
        $d_cfg  = "visualwincomp.txt" ascii
        $d_dir  = "GameFiles" ascii
        $d_pub  = "C:\\Users\\Public\\Downloads" ascii

        // --- self-delete (ASCII; weak/generic on its own) ---
        $sd     = "cmd.exe /c ping 127.0.0.1 -n 6 > nul && del /f /q" ascii

        // --- masquerade / version-info (note the misspelling) ---
        $v_desc = "DISPLAY drives Handeler" ascii wide
        $v_int  = "DIDS.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        (
            pe.imphash() == "9963ebabcee092908eac2414f7c4661a"
            or ($ua and $host)
            or (4 of ($u_*))
            or (1 of ($j_*) and 1 of ($g_*))
            or ($sd and 1 of ($d_*))
            or (1 of ($v_*) and ($d_dll or $d_cfg))
        )
}

rule MuddyWater_Stagecomp_KnownSample
{
    meta:
        description = "Exact known Stagecomp sample (hash pin)"
        author      = "Yanky Wilson (github.com/yankywilson)"
        date        = "2026-06-11"
        tlp         = "TLP:CLEAR"
    condition:
        hash.sha256(0, filesize) == "a92d28f1d32e3a9ab7c3691f8bfca8f7586bb0666adbba47eab3e1a8faf7ecc0"
}
