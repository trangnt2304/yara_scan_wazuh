rule win_urlzone_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.urlzone."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.urlzone"
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
        $sequence_0 = { 80f866 7f0c 80e861 80c00a }
            // n = 4, score = 3000
            //   80f866               | cmp                 al, 0x66
            //   7f0c                 | jg                  0xe
            //   80e861               | sub                 al, 0x61
            //   80c00a               | add                 al, 0xa

        $sequence_1 = { 31c0 85d2 7428 31c9 8a0a }
            // n = 5, score = 3000
            //   31c0                 | xor                 eax, eax
            //   85d2                 | test                edx, edx
            //   7428                 | je                  0x2a
            //   31c9                 | xor                 ecx, ecx
            //   8a0a                 | mov                 cl, byte ptr [edx]

        $sequence_2 = { 8d45fc 50 68???????? 6a00 6a00 a1???????? 50 }
            // n = 7, score = 3000
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   68????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   a1????????           |                     
            //   50                   | push                eax

        $sequence_3 = { 80fc39 7f05 80ec30 eb22 }
            // n = 4, score = 3000
            //   80fc39               | cmp                 ah, 0x39
            //   7f05                 | jg                  7
            //   80ec30               | sub                 ah, 0x30
            //   eb22                 | jmp                 0x24

        $sequence_4 = { 80f92b 7503 8a0a 42 }
            // n = 4, score = 3000
            //   80f92b               | cmp                 cl, 0x2b
            //   7503                 | jne                 5
            //   8a0a                 | mov                 cl, byte ptr [edx]
            //   42                   | inc                 edx

        $sequence_5 = { eb22 80f841 7c23 80f846 7f08 80e841 }
            // n = 6, score = 3000
            //   eb22                 | jmp                 0x24
            //   80f841               | cmp                 al, 0x41
            //   7c23                 | jl                  0x25
            //   80f846               | cmp                 al, 0x46
            //   7f08                 | jg                  0xa
            //   80e841               | sub                 al, 0x41

        $sequence_6 = { 80ec30 eb22 80fc41 7c54 80fc46 7f08 }
            // n = 6, score = 3000
            //   80ec30               | sub                 ah, 0x30
            //   eb22                 | jmp                 0x24
            //   80fc41               | cmp                 ah, 0x41
            //   7c54                 | jl                  0x56
            //   80fc46               | cmp                 ah, 0x46
            //   7f08                 | jg                  0xa

        $sequence_7 = { 80f830 7c32 80f839 7f05 80e830 eb22 }
            // n = 6, score = 3000
            //   80f830               | cmp                 al, 0x30
            //   7c32                 | jl                  0x34
            //   80f839               | cmp                 al, 0x39
            //   7f05                 | jg                  7
            //   80e830               | sub                 al, 0x30
            //   eb22                 | jmp                 0x24

        $sequence_8 = { 8d45f0 50 8b45f0 50 }
            // n = 4, score = 3000
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   50                   | push                eax

        $sequence_9 = { 33c0 8945ec 33c0 8945e8 }
            // n = 4, score = 3000
            //   33c0                 | xor                 eax, eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   33c0                 | xor                 eax, eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

    condition:
        7 of them and filesize < 704512
}