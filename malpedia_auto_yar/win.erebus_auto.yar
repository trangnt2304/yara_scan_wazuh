rule win_erebus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.erebus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.erebus"
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
        $sequence_0 = { 8b830c020000 8bf2 ff75cc 85c0 b9???????? ff75dc 0f45f0 }
            // n = 7, score = 100
            //   8b830c020000         | mov                 eax, dword ptr [ebx + 0x20c]
            //   8bf2                 | mov                 esi, edx
            //   ff75cc               | push                dword ptr [ebp - 0x34]
            //   85c0                 | test                eax, eax
            //   b9????????           |                     
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   0f45f0               | cmovne              esi, eax

        $sequence_1 = { 894c2410 8d04b8 3bd0 770e 8d42fc 8d04b8 3bc5 }
            // n = 7, score = 100
            //   894c2410             | mov                 dword ptr [esp + 0x10], ecx
            //   8d04b8               | lea                 eax, [eax + edi*4]
            //   3bd0                 | cmp                 edx, eax
            //   770e                 | ja                  0x10
            //   8d42fc               | lea                 eax, [edx - 4]
            //   8d04b8               | lea                 eax, [eax + edi*4]
            //   3bc5                 | cmp                 eax, ebp

        $sequence_2 = { 8d4c246c e8???????? 8b542414 51 8d8c2464010000 e8???????? 83c404 }
            // n = 7, score = 100
            //   8d4c246c             | lea                 ecx, [esp + 0x6c]
            //   e8????????           |                     
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   51                   | push                ecx
            //   8d8c2464010000       | lea                 ecx, [esp + 0x164]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_3 = { ff5024 8d4c2424 e8???????? 8d4c2474 c68424b000000005 e8???????? 8d4c244c }
            // n = 7, score = 100
            //   ff5024               | call                dword ptr [eax + 0x24]
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   e8????????           |                     
            //   8d4c2474             | lea                 ecx, [esp + 0x74]
            //   c68424b000000005     | mov                 byte ptr [esp + 0xb0], 5
            //   e8????????           |                     
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]

        $sequence_4 = { c3 8b4508 b906000000 5f 5e 8988c0030000 8bc3 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   b906000000           | mov                 ecx, 6
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8988c0030000         | mov                 dword ptr [eax + 0x3c0], ecx
            //   8bc3                 | mov                 eax, ebx

        $sequence_5 = { 84c0 0f8490000000 8b4c241c e8???????? 8bd7 8d4c2434 e8???????? }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   0f8490000000         | je                  0x96
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   e8????????           |                     
            //   8bd7                 | mov                 edx, edi
            //   8d4c2434             | lea                 ecx, [esp + 0x34]
            //   e8????????           |                     

        $sequence_6 = { 8d4e0c 6a06 8d9094fc5100 5f 668b02 8d5202 668901 }
            // n = 7, score = 100
            //   8d4e0c               | lea                 ecx, [esi + 0xc]
            //   6a06                 | push                6
            //   8d9094fc5100         | lea                 edx, [eax + 0x51fc94]
            //   5f                   | pop                 edi
            //   668b02               | mov                 ax, word ptr [edx]
            //   8d5202               | lea                 edx, [edx + 2]
            //   668901               | mov                 word ptr [ecx], ax

        $sequence_7 = { ffb688860000 ff15???????? 83c404 899e88860000 8d431b 5f 5e }
            // n = 7, score = 100
            //   ffb688860000         | push                dword ptr [esi + 0x8688]
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   899e88860000         | mov                 dword ptr [esi + 0x8688], ebx
            //   8d431b               | lea                 eax, [ebx + 0x1b]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_8 = { 8b742468 89470c 897c2410 c744240c04000000 c7471400000000 c744246002000000 33c9 }
            // n = 7, score = 100
            //   8b742468             | mov                 esi, dword ptr [esp + 0x68]
            //   89470c               | mov                 dword ptr [edi + 0xc], eax
            //   897c2410             | mov                 dword ptr [esp + 0x10], edi
            //   c744240c04000000     | mov                 dword ptr [esp + 0xc], 4
            //   c7471400000000       | mov                 dword ptr [edi + 0x14], 0
            //   c744246002000000     | mov                 dword ptr [esp + 0x60], 2
            //   33c9                 | xor                 ecx, ecx

        $sequence_9 = { c1e002 5b 5d c3 55 8bec 83ec08 }
            // n = 7, score = 100
            //   c1e002               | shl                 eax, 2
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec08               | sub                 esp, 8

    condition:
        7 of them and filesize < 2564096
}