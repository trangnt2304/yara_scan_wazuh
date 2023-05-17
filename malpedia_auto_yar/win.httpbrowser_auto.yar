rule win_httpbrowser_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.httpbrowser."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.httpbrowser"
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
        $sequence_0 = { 53 ffb5c8fbffff ff15???????? 85c0 0f8430ffffff 56 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   ffb5c8fbffff         | push                dword ptr [ebp - 0x438]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8430ffffff         | je                  0xffffff36
            //   56                   | push                esi

        $sequence_1 = { 85c0 740d 8d85f0fdffff 50 }
            // n = 4, score = 200
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]
            //   50                   | push                eax

        $sequence_2 = { 8d85fdeeffff 53 50 8bf9 }
            // n = 4, score = 200
            //   8d85fdeeffff         | lea                 eax, [ebp - 0x1103]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8bf9                 | mov                 edi, ecx

        $sequence_3 = { 8d85dcf9ffff 50 ffd3 68???????? 8d85dcf9ffff 50 }
            // n = 6, score = 200
            //   8d85dcf9ffff         | lea                 eax, [ebp - 0x624]
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   68????????           |                     
            //   8d85dcf9ffff         | lea                 eax, [ebp - 0x624]
            //   50                   | push                eax

        $sequence_4 = { 2bc6 50 57 53 53 }
            // n = 5, score = 200
            //   2bc6                 | sub                 eax, esi
            //   50                   | push                eax
            //   57                   | push                edi
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_5 = { 57 50 e8???????? 83c40c 33c0 56 668985e8fbffff }
            // n = 7, score = 200
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   33c0                 | xor                 eax, eax
            //   56                   | push                esi
            //   668985e8fbffff       | mov                 word ptr [ebp - 0x418], ax

        $sequence_6 = { 68ff030000 8d85f9fbffff 53 50 8bf1 889df8fbffff e8???????? }
            // n = 7, score = 200
            //   68ff030000           | push                0x3ff
            //   8d85f9fbffff         | lea                 eax, [ebp - 0x407]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   8bf1                 | mov                 esi, ecx
            //   889df8fbffff         | mov                 byte ptr [ebp - 0x408], bl
            //   e8????????           |                     

        $sequence_7 = { 53 68???????? 51 68???????? 50 8995f0fdffff }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   68????????           |                     
            //   51                   | push                ecx
            //   68????????           |                     
            //   50                   | push                eax
            //   8995f0fdffff         | mov                 dword ptr [ebp - 0x210], edx

        $sequence_8 = { 8d0c49 5e 8d0c8df8254100 3bc1 7304 3910 7402 }
            // n = 7, score = 100
            //   8d0c49               | lea                 ecx, [ecx + ecx*2]
            //   5e                   | pop                 esi
            //   8d0c8df8254100       | lea                 ecx, [ecx*4 + 0x4125f8]
            //   3bc1                 | cmp                 eax, ecx
            //   7304                 | jae                 6
            //   3910                 | cmp                 dword ptr [eax], edx
            //   7402                 | je                  4

        $sequence_9 = { ff15???????? 85c0 0f845f040000 8d85c8fdffff 68???????? }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f845f040000         | je                  0x465
            //   8d85c8fdffff         | lea                 eax, [ebp - 0x238]
            //   68????????           |                     

        $sequence_10 = { 53 56 57 33d2 b93f000000 33c0 8dbdfefdffff }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33d2                 | xor                 edx, edx
            //   b93f000000           | mov                 ecx, 0x3f
            //   33c0                 | xor                 eax, eax
            //   8dbdfefdffff         | lea                 edi, [ebp - 0x202]

        $sequence_11 = { ff15???????? 3de5030000 0f84e1000000 ff15???????? }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   3de5030000           | cmp                 eax, 0x3e5
            //   0f84e1000000         | je                  0xe7
            //   ff15????????         |                     

        $sequence_12 = { 33c0 8dbd16f5ffff 66899514f5ffff f3ab }
            // n = 4, score = 100
            //   33c0                 | xor                 eax, eax
            //   8dbd16f5ffff         | lea                 edi, [ebp - 0xaea]
            //   66899514f5ffff       | mov                 word ptr [ebp - 0xaec], dx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_13 = { 53 56 33f6 57 8d45fc 56 50 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   57                   | push                edi
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_14 = { b906000000 be???????? 8d7dac 6a18 8d45ac }
            // n = 5, score = 100
            //   b906000000           | mov                 ecx, 6
            //   be????????           |                     
            //   8d7dac               | lea                 edi, [ebp - 0x54]
            //   6a18                 | push                0x18
            //   8d45ac               | lea                 eax, [ebp - 0x54]

        $sequence_15 = { 85c9 741b 8b4514 8d55fc 52 56 }
            // n = 6, score = 100
            //   85c9                 | test                ecx, ecx
            //   741b                 | je                  0x1d
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8d55fc               | lea                 edx, [ebp - 4]
            //   52                   | push                edx
            //   56                   | push                esi

    condition:
        7 of them and filesize < 188416
}