rule win_lemonduck_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.lemonduck."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lemonduck"
        malpedia_rule_date = "20230328"
        malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
        malpedia_version = "20230407"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { ff5040 4c8bc8 49c7c4ffffffff 498bfc 48ffc7 803c3800 75f7 }
            // n = 7, score = 100
            //   ff5040               | test                dword ptr [ebx + 0x58], 0x20000000
            //   4c8bc8               | cmp                 eax, -1
            //   49c7c4ffffffff       | jne                 0x108
            //   498bfc               | mov                 ecx, eax
            //   48ffc7               | dec                 eax
            //   803c3800             | add                 esp, 0x40
            //   75f7                 | pop                 ebx

        $sequence_1 = { c1e908 81c100010000 410fb6d1 41c1e908 448b9490509d1600 488d15fdb6f9ff 4433948a509d1600 }
            // n = 7, score = 100
            //   c1e908               | inc                 ecx
            //   81c100010000         | shr                 eax, 0x18
            //   410fb6d1             | inc                 ecx
            //   41c1e908             | movzx               eax, byte ptr [esi + 0xe]
            //   448b9490509d1600     | inc                 esp
            //   488d15fdb6f9ff       | or                  eax, edx
            //   4433948a509d1600     | inc                 esp

        $sequence_2 = { ff15???????? 488bf8 4883f8ff 7522 ff15???????? 8bc8 89834c010000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488bf8               | dec                 eax
            //   4883f8ff             | mov                 ecx, edi
            //   7522                 | dec                 eax
            //   ff15????????         |                     
            //   8bc8                 | mov                 ebx, dword ptr [esp + 0x30]
            //   89834c010000         | dec                 eax

        $sequence_3 = { e8???????? 4c8b5b20 41bf00000800 488b4b38 48334b18 488b7328 4c331b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8b5b20             | mov                 dword ptr [esp + 0x20], eax
            //   41bf00000800         | mov                 dword ptr [esp + 0x28], 7
            //   488b4b38             | dec                 eax
            //   48334b18             | lea                 eax, [0x118154]
            //   488b7328             | dec                 eax
            //   4c331b               | mov                 dword ptr [ebp - 0x50], eax

        $sequence_4 = { ff5270 4c39bb88000000 75df 488b4360 48894378 4885c0 741a }
            // n = 7, score = 100
            //   ff5270               | jne                 0xaec
            //   4c39bb88000000       | mov                 eax, 0xfffff027
            //   75df                 | test                eax, eax
            //   488b4360             | jne                 0xb97
            //   48894378             | mov                 eax, 0xffffffff
            //   4885c0               | dec                 eax
            //   741a                 | mov                 ecx, dword ptr [esp + 0x30]

        $sequence_5 = { 4d85c9 0f8439010000 48c7858000000000000000 48c785880000000f000000 c6457000 41b80a000000 488d15b4b21300 }
            // n = 7, score = 100
            //   4d85c9               | mov                 esi, dword ptr [edi + 0x10]
            //   0f8439010000         | dec                 ebp
            //   48c7858000000000000000     | mov    esi, dword ptr [edi + 0x18]
            //   48c785880000000f000000     | dec    ebp
            //   c6457000             | add                 esi, esp
            //   41b80a000000         | dec                 eax
            //   488d15b4b21300       | cmp                 esi, 5

        $sequence_6 = { e8???????? 488d043b 4889442470 488bd6 488d4c2470 e8???????? 488b5c2470 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d043b             | dec                 eax
            //   4889442470           | lea                 ecx, [esp + 0x50]
            //   488bd6               | mulsd               xmm6, qword ptr [ebx + 0x28]
            //   488d4c2470           | movsd               qword ptr [esp + 0x50], xmm6
            //   e8????????           |                     
            //   488b5c2470           | dec                 eax

        $sequence_7 = { 66440f6f742440 660f6cc8 660fef4c2470 660f7f4c2470 66490f7ec8 49f7e7 66480f6ec0 }
            // n = 7, score = 100
            //   66440f6f742440       | nop                 dword ptr [eax]
            //   660f6cc8             | dec                 eax
            //   660fef4c2470         | mov                 edi, dword ptr [ebx]
            //   660f7f4c2470         | dec                 eax
            //   66490f7ec8           | mov                 ecx, esi
            //   49f7e7               | inc                 cx
            //   66480f6ec0           | cmp                 dword ptr [eax + 0xe], 3

        $sequence_8 = { 660f6cd2 660f6dee 660f6dda 660f6dc1 f30f7fa8f0000000 f30f7f98f0feffff f30f7f4070 }
            // n = 7, score = 100
            //   660f6cd2             | pxor                xmm3, xmm0
            //   660f6dee             | dec                 esp
            //   660f6dda             | mov                 ebp, dword ptr [ebp - 0x60]
            //   660f6dc1             | dec                 eax
            //   f30f7fa8f0000000     | lea                 eax, [esp + 0x40]
            //   f30f7f98f0feffff     | dec                 eax
            //   f30f7f4070           | mov                 dword ptr [esp + 0x30], eax

        $sequence_9 = { f30f7f8580000000 c6457000 c744245000020000 488b4df8 f6c102 7521 488b45c8 }
            // n = 7, score = 100
            //   f30f7f8580000000     | paddd               xmm2, xmm0
            //   c6457000             | dec                 eax
            //   c744245000020000     | add                 ecx, ecx
            //   488b4df8             | pmulld              xmm2, xmm1
            //   f6c102               | pmovzxdq            xmm0, xmm2
            //   7521                 | movq                xmm0, xmm3
            //   488b45c8             | paddd               xmm2, xmm0

    condition:
        7 of them and filesize < 10011648
}