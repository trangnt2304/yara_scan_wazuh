rule win_marap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.marap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.marap"
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
        $sequence_0 = { ebcf 85c9 7551 5f 898ee41d0000 8d4101 5b }
            // n = 7, score = 100
            //   ebcf                 | jmp                 0xffffffd1
            //   85c9                 | test                ecx, ecx
            //   7551                 | jne                 0x53
            //   5f                   | pop                 edi
            //   898ee41d0000         | mov                 dword ptr [esi + 0x1de4], ecx
            //   8d4101               | lea                 eax, [ecx + 1]
            //   5b                   | pop                 ebx

        $sequence_1 = { 50 ff15???????? 85c0 7425 8b480c 8b11 8b02 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7425                 | je                  0x27
            //   8b480c               | mov                 ecx, dword ptr [eax + 0xc]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b02                 | mov                 eax, dword ptr [edx]

        $sequence_2 = { 59 ebcf 8bc6 c1f805 8b048580320110 83e61f }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   ebcf                 | jmp                 0xffffffd1
            //   8bc6                 | mov                 eax, esi
            //   c1f805               | sar                 eax, 5
            //   8b048580320110       | mov                 eax, dword ptr [eax*4 + 0x10013280]
            //   83e61f               | and                 esi, 0x1f

        $sequence_3 = { 8dbef20c0000 57 e8???????? 83c404 66833f00 }
            // n = 5, score = 100
            //   8dbef20c0000         | lea                 edi, [esi + 0xcf2]
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   66833f00             | cmp                 word ptr [edi], 0

        $sequence_4 = { 8945f4 8b4514 40 c745ec7f910010 894df8 8945fc }
            // n = 6, score = 100
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   40                   | inc                 eax
            //   c745ec7f910010       | mov                 dword ptr [ebp - 0x14], 0x1000917f
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_5 = { c745ec7f910010 894df8 8945fc 64a100000000 8945e8 }
            // n = 5, score = 100
            //   c745ec7f910010       | mov                 dword ptr [ebp - 0x14], 0x1000917f
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_6 = { c1f805 8bf7 83e61f c1e606 03348580320110 c745e401000000 }
            // n = 6, score = 100
            //   c1f805               | sar                 eax, 5
            //   8bf7                 | mov                 esi, edi
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   03348580320110       | add                 esi, dword ptr [eax*4 + 0x10013280]
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1

        $sequence_7 = { 83c40c 8d4c2410 51 6802020000 ff15???????? 6800010000 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   51                   | push                ecx
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   6800010000           | push                0x100

        $sequence_8 = { c745e0a4b10010 817de0a8b10010 7311 8b45e0 }
            // n = 4, score = 100
            //   c745e0a4b10010       | mov                 dword ptr [ebp - 0x20], 0x1000b1a4
            //   817de0a8b10010       | cmp                 dword ptr [ebp - 0x20], 0x1000b1a8
            //   7311                 | jae                 0x13
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_9 = { 751c 8a55fa feca 0fb6c2 f7d8 1bc0 2558020000 }
            // n = 7, score = 100
            //   751c                 | jne                 0x1e
            //   8a55fa               | mov                 dl, byte ptr [ebp - 6]
            //   feca                 | dec                 dl
            //   0fb6c2               | movzx               eax, dl
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   2558020000           | and                 eax, 0x258

    condition:
        7 of them and filesize < 188416
}