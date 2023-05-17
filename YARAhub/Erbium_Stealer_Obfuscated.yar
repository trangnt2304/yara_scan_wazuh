rule Erbium_Stealer_Obfuscated
{
    meta:
        author                    = "@_FirehaK <yara@firehak.com>"
        date                      = "2022-09-02"
        description               = "Erbium Stealer in its obfuscated format"
        malpedia_family           = "win.erbium_stealer"
        modified                  = "2022-09-09"
        yarahub_author_twitter    = "@_FirehaK"
        yarahub_author_email      = "yara@firehak.com"
        yarahub_reference_link    = "https://tria.ge/220902-mbcs1seef7"
        yarahub_reference_md5     = "71c3772dd2f4c60a13e3e5a1180154b7"
        yarahub_uuid              = "29756611-4992-4ff5-b2cb-ffe867dfb823"
        yarahub_license           = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"

    strings:
        // <space>Zig Zig Zig
        $zig = { 20 5A 69 67 20 5A 69 67 20 5A 69 67 }
        // ZigRich Zig
        $richzig = { 5A 69 67 52 69 63 68 20 5A 69 67 }

        $x1 = { e800000000 8b0424 83042408 c3 }
        $x2 = { 64a130000000 8b400c 8985????ffff 8b85????ffff 8b400c 8985????ffff }
        $x3 = { b8???????? f7ea 035424?? c1fa?? 8bc2 c1e8?? 03c2 8b5424?? 0fbec0 8aca 6bc039 2ac8 80c137 304c14?? 42 895424?? 83fa?? 7c }
        $x4 = { 33d2 8bc1 f7f6 80c2?? 30?40c(??|????0000) 41 83f9?? 7c }
        $x5 = { 8b??????ffff 03??????ffff 0fbe?? 8b85????ffff 99 be??000000 f7fe 83c2?? 33ca 8b95????ffff 0395????ffff 880a eb }
        $x6 = { 8b45?? 0fbe4c05?? 8b45?? 99 be??000000 f7fe 83c2?? 33ca 8b55?? 884c15?? eb }
        $x7 = { 6a05 68???????? 6a00 68????0000 e8???????? 83c410 33d2 b915000000 f7f1 8955?? 837d??00 75?? 6a?? 68???????? 6a?? 68????0000 e8???????? 83c4?? 33d2 b910270000 f7f1 8995????ffff }
        $x8 = { 6a05 68???????? 6a00 68????0000 e8???????? 83c410 33d2 6a?? 59 f7f1 8955?? 837d??00 75?? 6a05 68???????? 6a00 68????0000 e8???????? 83c410 33d2 b910270000 f7f1 8995????ffff }
        $x9 = { 6910???????? 83c0?? 69db???????? 8bca c1e918 33ca 69d1???????? 33da 83ef?? 75 }

    condition:
        uint16(0) == 0x5a4d
        and (
            (
                $zig
                and $richzig
                and 2 of ($x*)
            )
            or 3 of ($x*)
        )
}