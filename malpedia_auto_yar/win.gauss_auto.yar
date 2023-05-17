rule win_gauss_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.gauss."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gauss"
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
        $sequence_0 = { e8???????? 894508 8945ec c645fc01 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_1 = { e8???????? 8b4c2408 898880000000 8bc6 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   898880000000         | mov                 dword ptr [eax + 0x80], ecx
            //   8bc6                 | mov                 eax, esi

        $sequence_2 = { 33db 895de4 66895dd4 895dfc c645fc01 }
            // n = 5, score = 700
            //   33db                 | xor                 ebx, ebx
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   66895dd4             | mov                 word ptr [ebp - 0x2c], bx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_3 = { 56 e8???????? 8bb080000000 e8???????? 8b4c2408 }
            // n = 5, score = 700
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bb080000000         | mov                 esi, dword ptr [eax + 0x80]
            //   e8????????           |                     
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]

        $sequence_4 = { 53 56 57 8965f0 8b7508 e8???????? }
            // n = 6, score = 700
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_5 = { cc 833e00 7505 e8???????? }
            // n = 4, score = 600
            //   cc                   | int3                
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_6 = { e8???????? c7442414ffffffff 8b4c240c 5f 8bc6 }
            // n = 5, score = 600
            //   e8????????           |                     
            //   c7442414ffffffff     | mov                 dword ptr [esp + 0x14], 0xffffffff
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi

        $sequence_7 = { 66832600 33c0 3bc7 1bc0 f7d8 5e }
            // n = 6, score = 600
            //   66832600             | and                 word ptr [esi], 0
            //   33c0                 | xor                 eax, eax
            //   3bc7                 | cmp                 eax, edi
            //   1bc0                 | sbb                 eax, eax
            //   f7d8                 | neg                 eax
            //   5e                   | pop                 esi

        $sequence_8 = { 85ff 7514 217e14 83f808 }
            // n = 4, score = 600
            //   85ff                 | test                edi, edi
            //   7514                 | jne                 0x16
            //   217e14               | and                 dword ptr [esi + 0x14], edi
            //   83f808               | cmp                 eax, 8

        $sequence_9 = { 7205 8b4004 eb03 83c004 6683244800 }
            // n = 5, score = 600
            //   7205                 | jb                  7
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   eb03                 | jmp                 5
            //   83c004               | add                 eax, 4
            //   6683244800           | and                 word ptr [eax + ecx*2], 0

        $sequence_10 = { 8bf0 7605 e8???????? 8b4618 3bc7 730c }
            // n = 6, score = 600
            //   8bf0                 | mov                 esi, eax
            //   7605                 | jbe                 7
            //   e8????????           |                     
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]
            //   3bc7                 | cmp                 eax, edi
            //   730c                 | jae                 0xe

        $sequence_11 = { 56 8bf0 395e14 57 7305 }
            // n = 5, score = 600
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   395e14               | cmp                 dword ptr [esi + 0x14], ebx
            //   57                   | push                edi
            //   7305                 | jae                 7

        $sequence_12 = { e8???????? c7442410ffffffff 8b4c2408 8bc6 5e 64890d00000000 }
            // n = 6, score = 600
            //   e8????????           |                     
            //   c7442410ffffffff     | mov                 dword ptr [esp + 0x10], 0xffffffff
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_13 = { 56 8d4508 8bf1 50 8975f0 e8???????? }
            // n = 6, score = 600
            //   56                   | push                esi
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8bf1                 | mov                 esi, ecx
            //   50                   | push                eax
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   e8????????           |                     

        $sequence_14 = { 8b7604 eb03 83c604 66832600 33c0 }
            // n = 5, score = 600
            //   8b7604               | mov                 esi, dword ptr [esi + 4]
            //   eb03                 | jmp                 5
            //   83c604               | add                 esi, 4
            //   66832600             | and                 word ptr [esi], 0
            //   33c0                 | xor                 eax, eax

        $sequence_15 = { ff742408 8bf0 83661400 c7461807000000 6683660400 e8???????? }
            // n = 6, score = 600
            //   ff742408             | push                dword ptr [esp + 8]
            //   8bf0                 | mov                 esi, eax
            //   83661400             | and                 dword ptr [esi + 0x14], 0
            //   c7461807000000       | mov                 dword ptr [esi + 0x18], 7
            //   6683660400           | and                 word ptr [esi + 4], 0
            //   e8????????           |                     

    condition:
        7 of them and filesize < 827392
}