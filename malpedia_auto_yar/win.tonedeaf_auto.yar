rule win_tonedeaf_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.tonedeaf."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tonedeaf"
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
        $sequence_0 = { 2bd9 2bf1 8bc3 46 d1e8 33d2 }
            // n = 6, score = 400
            //   2bd9                 | sub                 ebx, ecx
            //   2bf1                 | sub                 esi, ecx
            //   8bc3                 | mov                 eax, ebx
            //   46                   | inc                 esi
            //   d1e8                 | shr                 eax, 1
            //   33d2                 | xor                 edx, edx

        $sequence_1 = { 722f f645e41f 7405 e8???????? 8b46fc 3bc6 7205 }
            // n = 7, score = 400
            //   722f                 | jb                  0x31
            //   f645e41f             | test                byte ptr [ebp - 0x1c], 0x1f
            //   7405                 | je                  7
            //   e8????????           |                     
            //   8b46fc               | mov                 eax, dword ptr [esi - 4]
            //   3bc6                 | cmp                 eax, esi
            //   7205                 | jb                  7

        $sequence_2 = { 8b45ec 85c0 740b 6a08 50 e8???????? }
            // n = 6, score = 400
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   85c0                 | test                eax, eax
            //   740b                 | je                  0xd
            //   6a08                 | push                8
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 33c0 660fd645d4 33db 8945d8 }
            // n = 4, score = 400
            //   33c0                 | xor                 eax, eax
            //   660fd645d4           | movq                qword ptr [ebp - 0x2c], xmm0
            //   33db                 | xor                 ebx, ebx
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax

        $sequence_4 = { f645e41f 7405 e8???????? 8b46fc 3bc6 }
            // n = 5, score = 400
            //   f645e41f             | test                byte ptr [ebp - 0x1c], 0x1f
            //   7405                 | je                  7
            //   e8????????           |                     
            //   8b46fc               | mov                 eax, dword ptr [esi - 4]
            //   3bc6                 | cmp                 eax, esi

        $sequence_5 = { 83f801 732f 8b0f 8bc1 }
            // n = 4, score = 400
            //   83f801               | cmp                 eax, 1
            //   732f                 | jae                 0x31
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8bc1                 | mov                 eax, ecx

        $sequence_6 = { 75f3 8bf3 8a03 43 84c0 75f9 2bde }
            // n = 7, score = 400
            //   75f3                 | jne                 0xfffffff5
            //   8bf3                 | mov                 esi, ebx
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   43                   | inc                 ebx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   2bde                 | sub                 ebx, esi

        $sequence_7 = { 8b5004 8d4af8 898c153cffffff 8d45a8 }
            // n = 4, score = 400
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8d4af8               | lea                 ecx, [edx - 8]
            //   898c153cffffff       | mov                 dword ptr [ebp + edx - 0xc4], ecx
            //   8d45a8               | lea                 eax, [ebp - 0x58]

        $sequence_8 = { c745dc00000000 33c0 660fd645d4 33db 8945d8 895dd4 8945dc }
            // n = 7, score = 400
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   33c0                 | xor                 eax, eax
            //   660fd645d4           | movq                qword ptr [ebp - 0x2c], xmm0
            //   33db                 | xor                 ebx, ebx
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   895dd4               | mov                 dword ptr [ebp - 0x2c], ebx
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax

        $sequence_9 = { f645e41f 7405 e8???????? 8b46fc }
            // n = 4, score = 400
            //   f645e41f             | test                byte ptr [ebp - 0x1c], 0x1f
            //   7405                 | je                  7
            //   e8????????           |                     
            //   8b46fc               | mov                 eax, dword ptr [esi - 4]

    condition:
        7 of them and filesize < 851968
}