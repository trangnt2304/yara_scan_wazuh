rule win_dexter_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.dexter."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dexter"
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
        $sequence_0 = { 3b450c 7d32 e8???????? 99 }
            // n = 4, score = 400
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   7d32                 | jge                 0x34
            //   e8????????           |                     
            //   99                   | cdq                 

        $sequence_1 = { 034508 894508 8b5508 83c201 }
            // n = 4, score = 400
            //   034508               | add                 eax, dword ptr [ebp + 8]
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83c201               | add                 edx, 1

        $sequence_2 = { 7d32 e8???????? 99 b919000000 f7f9 }
            // n = 5, score = 400
            //   7d32                 | jge                 0x34
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b919000000           | mov                 ecx, 0x19
            //   f7f9                 | idiv                ecx

        $sequence_3 = { 68???????? 8b4d0c 51 e8???????? 83c410 8b55fc d1e2 }
            // n = 7, score = 400
            //   68????????           |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   d1e2                 | shl                 edx, 1

        $sequence_4 = { 0f85bc000000 e8???????? a3???????? 6808020000 6a00 68???????? }
            // n = 6, score = 400
            //   0f85bc000000         | jne                 0xc2
            //   e8????????           |                     
            //   a3????????           |                     
            //   6808020000           | push                0x208
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_5 = { 6a00 ff15???????? a3???????? 6a05 }
            // n = 4, score = 400
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   a3????????           |                     
            //   6a05                 | push                5

        $sequence_6 = { 83c404 c745f401000000 eb17 837df400 7511 }
            // n = 5, score = 400
            //   83c404               | add                 esp, 4
            //   c745f401000000       | mov                 dword ptr [ebp - 0xc], 1
            //   eb17                 | jmp                 0x19
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7511                 | jne                 0x13

        $sequence_7 = { e8???????? 83c40c c705????????28010000 6a00 6a02 e8???????? }
            // n = 6, score = 400
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c705????????28010000     |     
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   e8????????           |                     

        $sequence_8 = { 51 ff15???????? ebc6 8be5 }
            // n = 4, score = 400
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   ebc6                 | jmp                 0xffffffc8
            //   8be5                 | mov                 esp, ebp

        $sequence_9 = { 8b4d0c 51 68???????? 8b5508 52 ff15???????? }
            // n = 6, score = 400
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   51                   | push                ecx
            //   68????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 98304
}