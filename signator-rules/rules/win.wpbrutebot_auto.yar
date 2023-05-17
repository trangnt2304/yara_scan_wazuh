rule win_wpbrutebot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.wpbrutebot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wpbrutebot"
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
        $sequence_0 = { e8???????? 8b4c2424 83c404 2bc8 898bb0100000 1bfa 89bbb4100000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   83c404               | add                 esp, 4
            //   2bc8                 | sub                 ecx, eax
            //   898bb0100000         | mov                 dword ptr [ebx + 0x10b0], ecx
            //   1bfa                 | sbb                 edi, edx
            //   89bbb4100000         | mov                 dword ptr [ebx + 0x10b4], edi

        $sequence_1 = { c745f864597d55 33c0 c645fc00 8d4809 304c05f8 40 83f804 }
            // n = 7, score = 100
            //   c745f864597d55       | mov                 dword ptr [ebp - 8], 0x557d5964
            //   33c0                 | xor                 eax, eax
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   8d4809               | lea                 ecx, [eax + 9]
            //   304c05f8             | xor                 byte ptr [ebp + eax - 8], cl
            //   40                   | inc                 eax
            //   83f804               | cmp                 eax, 4

        $sequence_2 = { 094554 03fe 2bde e9???????? 83f801 741b 68???????? }
            // n = 7, score = 100
            //   094554               | or                  dword ptr [ebp + 0x54], eax
            //   03fe                 | add                 edi, esi
            //   2bde                 | sub                 ebx, esi
            //   e9????????           |                     
            //   83f801               | cmp                 eax, 1
            //   741b                 | je                  0x1d
            //   68????????           |                     

        $sequence_3 = { f6404030 740b 6a05 57 e8???????? 83c408 c686fe04000001 }
            // n = 7, score = 100
            //   f6404030             | test                byte ptr [eax + 0x40], 0x30
            //   740b                 | je                  0xd
            //   6a05                 | push                5
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c686fe04000001       | mov                 byte ptr [esi + 0x4fe], 1

        $sequence_4 = { e8???????? cc 55 8bec 51 51 6a00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   6a00                 | push                0

        $sequence_5 = { e8???????? 8d8da8f4ffff e8???????? 8d8db0f6ffff e8???????? 8d8d3cfbffff e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d8da8f4ffff         | lea                 ecx, [ebp - 0xb58]
            //   e8????????           |                     
            //   8d8db0f6ffff         | lea                 ecx, [ebp - 0x950]
            //   e8????????           |                     
            //   8d8d3cfbffff         | lea                 ecx, [ebp - 0x4c4]
            //   e8????????           |                     

        $sequence_6 = { c1ea18 8b1c85382f6200 8b048d382b6200 8b4c246c c1e108 0b4c2470 c1e108 }
            // n = 7, score = 100
            //   c1ea18               | shr                 edx, 0x18
            //   8b1c85382f6200       | mov                 ebx, dword ptr [eax*4 + 0x622f38]
            //   8b048d382b6200       | mov                 eax, dword ptr [ecx*4 + 0x622b38]
            //   8b4c246c             | mov                 ecx, dword ptr [esp + 0x6c]
            //   c1e108               | shl                 ecx, 8
            //   0b4c2470             | or                  ecx, dword ptr [esp + 0x70]
            //   c1e108               | shl                 ecx, 8

        $sequence_7 = { ff15???????? 83c404 894708 85c0 0f843bfdffff be07000000 84db }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   894708               | mov                 dword ptr [edi + 8], eax
            //   85c0                 | test                eax, eax
            //   0f843bfdffff         | je                  0xfffffd41
            //   be07000000           | mov                 esi, 7
            //   84db                 | test                bl, bl

        $sequence_8 = { e8???????? 8bf8 c745ac0f000000 89bd48feffff c745a800000000 c6459800 c745dc0f000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   c745ac0f000000       | mov                 dword ptr [ebp - 0x54], 0xf
            //   89bd48feffff         | mov                 dword ptr [ebp - 0x1b8], edi
            //   c745a800000000       | mov                 dword ptr [ebp - 0x58], 0
            //   c6459800             | mov                 byte ptr [ebp - 0x68], 0
            //   c745dc0f000000       | mov                 dword ptr [ebp - 0x24], 0xf

        $sequence_9 = { ffb6940b0000 ffb6900b0000 e8???????? 83c40c 50 8d8424a2000000 50 }
            // n = 7, score = 100
            //   ffb6940b0000         | push                dword ptr [esi + 0xb94]
            //   ffb6900b0000         | push                dword ptr [esi + 0xb90]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   8d8424a2000000       | lea                 eax, [esp + 0xa2]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 5134336
}