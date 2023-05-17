rule win_ghostnet_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ghostnet"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
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
        $sequence_0 = { 8b45d4 50 8b45d0 50 8b45d8 50 6a04 }
            // n = 7, score = 200
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   50                   | push                eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   50                   | push                eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   50                   | push                eax
            //   6a04                 | push                4

        $sequence_1 = { 8bc5 33d2 52 50 8bce c1e102 8bc1 }
            // n = 7, score = 200
            //   8bc5                 | mov                 eax, ebp
            //   33d2                 | xor                 edx, edx
            //   52                   | push                edx
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   c1e102               | shl                 ecx, 2
            //   8bc1                 | mov                 eax, ecx

        $sequence_2 = { 7415 8b45fc e8???????? 8b45fc e8???????? e9???????? 33c0 }
            // n = 7, score = 200
            //   7415                 | je                  0x17
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { 55 68???????? 64ff30 648920 8b45fc 8b90a8000000 8b45f4 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   68????????           |                     
            //   64ff30               | push                dword ptr fs:[eax]
            //   648920               | mov                 dword ptr fs:[eax], esp
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b90a8000000         | mov                 edx, dword ptr [eax + 0xa8]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_4 = { 33db 8d442408 8b28 3bd5 7e05 8bd5 }
            // n = 6, score = 200
            //   33db                 | xor                 ebx, ebx
            //   8d442408             | lea                 eax, [esp + 8]
            //   8b28                 | mov                 ebp, dword ptr [eax]
            //   3bd5                 | cmp                 edx, ebp
            //   7e05                 | jle                 7
            //   8bd5                 | mov                 edx, ebp

        $sequence_5 = { ff75cc 68???????? 8d45f4 ba05000000 e8???????? 8b45f4 e8???????? }
            // n = 7, score = 200
            //   ff75cc               | push                dword ptr [ebp - 0x34]
            //   68????????           |                     
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   ba05000000           | mov                 edx, 5
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   e8????????           |                     

        $sequence_6 = { 8bd0 4a 740a 4a 7418 }
            // n = 5, score = 200
            //   8bd0                 | mov                 edx, eax
            //   4a                   | dec                 edx
            //   740a                 | je                  0xc
            //   4a                   | dec                 edx
            //   7418                 | je                  0x1a

        $sequence_7 = { 8b5854 8bc3 8b10 ff12 52 50 8bd3 }
            // n = 7, score = 200
            //   8b5854               | mov                 ebx, dword ptr [eax + 0x54]
            //   8bc3                 | mov                 eax, ebx
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff12                 | call                dword ptr [edx]
            //   52                   | push                edx
            //   50                   | push                eax
            //   8bd3                 | mov                 edx, ebx

        $sequence_8 = { ba64000000 e8???????? 8d85c4f7ffff 50 6b86a03a00004b 8d44866c }
            // n = 6, score = 200
            //   ba64000000           | mov                 edx, 0x64
            //   e8????????           |                     
            //   8d85c4f7ffff         | lea                 eax, [ebp - 0x83c]
            //   50                   | push                eax
            //   6b86a03a00004b       | imul                eax, dword ptr [esi + 0x3aa0], 0x4b
            //   8d44866c             | lea                 eax, [esi + eax*4 + 0x6c]

        $sequence_9 = { 5b c3 3c0d 7519 8bc1 e8???????? }
            // n = 6, score = 200
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   3c0d                 | cmp                 al, 0xd
            //   7519                 | jne                 0x1b
            //   8bc1                 | mov                 eax, ecx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 663552
}