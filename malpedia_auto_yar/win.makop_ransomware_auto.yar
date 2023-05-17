rule win_makop_ransomware_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.makop_ransomware."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.makop_ransomware"
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
        $sequence_0 = { 55 6aff 57 6a01 6800080000 81c6ffff0000 ffd3 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   6aff                 | push                -1
            //   57                   | push                edi
            //   6a01                 | push                1
            //   6800080000           | push                0x800
            //   81c6ffff0000         | add                 esi, 0xffff
            //   ffd3                 | call                ebx

        $sequence_1 = { 8b84244c010000 8bcb 51 8b8c244c010000 52 50 51 }
            // n = 7, score = 100
            //   8b84244c010000       | mov                 eax, dword ptr [esp + 0x14c]
            //   8bcb                 | mov                 ecx, ebx
            //   51                   | push                ecx
            //   8b8c244c010000       | mov                 ecx, dword ptr [esp + 0x14c]
            //   52                   | push                edx
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_2 = { 33f6 53 89742420 c644241b00 ff15???????? 85c0 0f84a0030000 }
            // n = 7, score = 100
            //   33f6                 | xor                 esi, esi
            //   53                   | push                ebx
            //   89742420             | mov                 dword ptr [esp + 0x20], esi
            //   c644241b00           | mov                 byte ptr [esp + 0x1b], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84a0030000         | je                  0x3a6

        $sequence_3 = { 7454 83bb3808000000 764b 8b842414080000 8bce }
            // n = 5, score = 100
            //   7454                 | je                  0x56
            //   83bb3808000000       | cmp                 dword ptr [ebx + 0x838], 0
            //   764b                 | jbe                 0x4d
            //   8b842414080000       | mov                 eax, dword ptr [esp + 0x814]
            //   8bce                 | mov                 ecx, esi

        $sequence_4 = { 8bf0 8916 c74604???????? 8b03 894614 8b4500 85c0 }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   8916                 | mov                 dword ptr [esi], edx
            //   c74604????????       |                     
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   85c0                 | test                eax, eax

        $sequence_5 = { e8???????? 83c40c 8d4e0c 51 66c7060802 66c746041066 c6460820 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4e0c               | lea                 ecx, [esi + 0xc]
            //   51                   | push                ecx
            //   66c7060802           | mov                 word ptr [esi], 0x208
            //   66c746041066         | mov                 word ptr [esi + 4], 0x6610
            //   c6460820             | mov                 byte ptr [esi + 8], 0x20

        $sequence_6 = { 50 51 ffd3 50 ffd7 8b4628 85c0 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b4628               | mov                 eax, dword ptr [esi + 0x28]
            //   85c0                 | test                eax, eax

        $sequence_7 = { ff15???????? 8b442420 50 6a00 ff15???????? 50 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_8 = { 0f94c0 a2???????? f6d8 1bc0 83e005 }
            // n = 5, score = 100
            //   0f94c0               | sete                al
            //   a2????????           |                     
            //   f6d8                 | neg                 al
            //   1bc0                 | sbb                 eax, eax
            //   83e005               | and                 eax, 5

        $sequence_9 = { 83e10f 8944241c 740d ba10000000 2bd1 03c2 }
            // n = 6, score = 100
            //   83e10f               | and                 ecx, 0xf
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   740d                 | je                  0xf
            //   ba10000000           | mov                 edx, 0x10
            //   2bd1                 | sub                 edx, ecx
            //   03c2                 | add                 eax, edx

    condition:
        7 of them and filesize < 107520
}