rule win_sienna_purple_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.sienna_purple."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sienna_purple"
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
        $sequence_0 = { e8???????? 68???????? 8bcb e8???????? ff7614 8bcb e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   ff7614               | push                dword ptr [esi + 0x14]
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_1 = { 8b5510 3bca 0f82d0fdffff 85f6 7413 8b8dbcfdffff 8d85e0fdffff }
            // n = 7, score = 100
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   3bca                 | cmp                 ecx, edx
            //   0f82d0fdffff         | jb                  0xfffffdd6
            //   85f6                 | test                esi, esi
            //   7413                 | je                  0x15
            //   8b8dbcfdffff         | mov                 ecx, dword ptr [ebp - 0x244]
            //   8d85e0fdffff         | lea                 eax, [ebp - 0x220]

        $sequence_2 = { e9???????? 0f57c0 c745b800000000 8d4da0 660fd645b0 f30f7f45a0 e8???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   0f57c0               | xorps               xmm0, xmm0
            //   c745b800000000       | mov                 dword ptr [ebp - 0x48], 0
            //   8d4da0               | lea                 ecx, [ebp - 0x60]
            //   660fd645b0           | movq                qword ptr [ebp - 0x50], xmm0
            //   f30f7f45a0           | movdqu              xmmword ptr [ebp - 0x60], xmm0
            //   e8????????           |                     

        $sequence_3 = { e8???????? 83c408 83f801 7530 8b45cc 8b4de0 8b55e4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   83f801               | cmp                 eax, 1
            //   7530                 | jne                 0x32
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]

        $sequence_4 = { c645fc01 50 8d8d60ffffff e8???????? 50 8d8d60ffffff e8???????? }
            // n = 7, score = 100
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   50                   | push                eax
            //   8d8d60ffffff         | lea                 ecx, [ebp - 0xa0]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d8d60ffffff         | lea                 ecx, [ebp - 0xa0]
            //   e8????????           |                     

        $sequence_5 = { 89759c 660fd645e4 c745ec00000000 e8???????? 80be2501000000 c745fc00000000 747b }
            // n = 7, score = 100
            //   89759c               | mov                 dword ptr [ebp - 0x64], esi
            //   660fd645e4           | movq                qword ptr [ebp - 0x1c], xmm0
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   e8????????           |                     
            //   80be2501000000       | cmp                 byte ptr [esi + 0x125], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   747b                 | je                  0x7d

        $sequence_6 = { c7421000000000 c7420800000000 394a0c 7e15 8d9b00000000 c70000000000 8d4004 }
            // n = 7, score = 100
            //   c7421000000000       | mov                 dword ptr [edx + 0x10], 0
            //   c7420800000000       | mov                 dword ptr [edx + 8], 0
            //   394a0c               | cmp                 dword ptr [edx + 0xc], ecx
            //   7e15                 | jle                 0x17
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   8d4004               | lea                 eax, [eax + 4]

        $sequence_7 = { 8d8f38030000 c645fc05 e8???????? 8d8f1c030000 c645fc04 e8???????? 8d8f00030000 }
            // n = 7, score = 100
            //   8d8f38030000         | lea                 ecx, [edi + 0x338]
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   e8????????           |                     
            //   8d8f1c030000         | lea                 ecx, [edi + 0x31c]
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   e8????????           |                     
            //   8d8f00030000         | lea                 ecx, [edi + 0x300]

        $sequence_8 = { 8d4e10 e8???????? 8b4d0c 8bf0 e8???????? c70365787061 8bf8 }
            // n = 7, score = 100
            //   8d4e10               | lea                 ecx, [esi + 0x10]
            //   e8????????           |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     
            //   c70365787061         | mov                 dword ptr [ebx], 0x61707865
            //   8bf8                 | mov                 edi, eax

        $sequence_9 = { f7d1 c1c306 23cf 895de4 23c3 0bc8 8bc7 }
            // n = 7, score = 100
            //   f7d1                 | not                 ecx
            //   c1c306               | rol                 ebx, 6
            //   23cf                 | and                 ecx, edi
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   23c3                 | and                 eax, ebx
            //   0bc8                 | or                  ecx, eax
            //   8bc7                 | mov                 eax, edi

    condition:
        7 of them and filesize < 2930688
}