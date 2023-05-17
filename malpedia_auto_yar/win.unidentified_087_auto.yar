rule win_unidentified_087_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-29"
        version = "1"
        description = "Detects win.unidentified_087."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_087"
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
        $sequence_0 = { 7205 4c8b03 eb03 4c8bc3 488bd7 }
            // n = 5, score = 200
            //   7205                 | jb                  7
            //   4c8b03               | dec                 esp
            //   eb03                 | mov                 eax, dword ptr [ebx]
            //   4c8bc3               | jmp                 5
            //   488bd7               | dec                 esp

        $sequence_1 = { 488bd7 488d4de7 e8???????? 90 bf01000000 }
            // n = 5, score = 200
            //   488bd7               | or                  ecx, 0xffffffff
            //   488d4de7             | inc                 ebp
            //   e8????????           |                     
            //   90                   | xor                 eax, eax
            //   bf01000000           | dec                 eax

        $sequence_2 = { 4533c0 e8???????? 90 4983c9ff }
            // n = 4, score = 200
            //   4533c0               | nop                 
            //   e8????????           |                     
            //   90                   | mov                 edi, 1
            //   4983c9ff             | inc                 ecx

        $sequence_3 = { 7205 488b0b eb03 488bcb 4983f910 7205 }
            // n = 6, score = 200
            //   7205                 | push                esp
            //   488b0b               | inc                 ecx
            //   eb03                 | push                ebp
            //   488bcb               | dec                 eax
            //   4983f910             | sub                 esp, 0x30
            //   7205                 | dec                 esp

        $sequence_4 = { 488d4597 488945bf 48c745af0f000000 48895da7 885d97 4983c9ff 4533c0 }
            // n = 7, score = 200
            //   488d4597             | mov                 eax, ebx
            //   488945bf             | dec                 eax
            //   48c745af0f000000     | mov                 edx, edi
            //   48895da7             | dec                 eax
            //   885d97               | lea                 eax, [ebp - 0x69]
            //   4983c9ff             | dec                 eax
            //   4533c0               | mov                 dword ptr [ebp - 0x41], eax

        $sequence_5 = { 4154 4155 4883ec30 4c8b4918 498be8 }
            // n = 5, score = 200
            //   4154                 | mov                 ecx, eax
            //   4155                 | mov                 dword ptr [esp + 0x20], 0x130
            //   4883ec30             | test                eax, eax
            //   4c8b4918             | je                  0x3a
            //   498be8               | cmp                 dword ptr [esp + 0x28], edi

        $sequence_6 = { eb36 48ff4708 41880424 49ffc4 4c89642478 }
            // n = 5, score = 200
            //   eb36                 | je                  0x29
            //   48ff4708             | dec                 eax
            //   41880424             | mov                 edx, edi
            //   49ffc4               | dec                 eax
            //   4c89642478           | lea                 ecx, [ebp - 0x19]

        $sequence_7 = { 488bc8 c744242030010000 ff15???????? 85c0 742b 397c2428 7414 }
            // n = 7, score = 200
            //   488bc8               | dec                 eax
            //   c744242030010000     | mov                 dword ptr [ebp - 0x51], 0xf
            //   ff15????????         |                     
            //   85c0                 | dec                 eax
            //   742b                 | mov                 dword ptr [ebp - 0x59], ebx
            //   397c2428             | mov                 byte ptr [ebp - 0x69], bl
            //   7414                 | dec                 ecx

        $sequence_8 = { 83c40c eb0a 8b0f 890d???????? 891f 8b5710 8915???????? }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   eb0a                 | jmp                 0xc
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   890d????????         |                     
            //   891f                 | mov                 dword ptr [edi], ebx
            //   8b5710               | mov                 edx, dword ptr [edi + 0x10]
            //   8915????????         |                     

        $sequence_9 = { 8945fc 8b450c 8b4d08 50 51 68???????? 8d55b8 }
            // n = 7, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   68????????           |                     
            //   8d55b8               | lea                 edx, [ebp - 0x48]

        $sequence_10 = { 3b85b4faffff 752b 8b4508 be10000000 39751c 7303 }
            // n = 6, score = 100
            //   3b85b4faffff         | cmp                 eax, dword ptr [ebp - 0x54c]
            //   752b                 | jne                 0x2d
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   be10000000           | mov                 esi, 0x10
            //   39751c               | cmp                 dword ptr [ebp + 0x1c], esi
            //   7303                 | jae                 5

        $sequence_11 = { 50 8d85e4feffff 50 0fb785d6faffff 51 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]
            //   50                   | push                eax
            //   0fb785d6faffff       | movzx               eax, word ptr [ebp - 0x52a]
            //   51                   | push                ecx

        $sequence_12 = { c744240c9cd10110 e8???????? 68???????? 8d442410 50 89742420 }
            // n = 6, score = 100
            //   c744240c9cd10110     | mov                 dword ptr [esp + 0xc], 0x1001d19c
            //   e8????????           |                     
            //   68????????           |                     
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   89742420             | mov                 dword ptr [esp + 0x20], esi

        $sequence_13 = { 4b 0fb60b 40 80b93810021000 }
            // n = 4, score = 100
            //   4b                   | dec                 ebx
            //   0fb60b               | movzx               ecx, byte ptr [ebx]
            //   40                   | inc                 eax
            //   80b93810021000       | cmp                 byte ptr [ecx + 0x10021038], 0

        $sequence_14 = { c6043800 42 89550c 3b55dc 0f8c7affffff }
            // n = 5, score = 100
            //   c6043800             | mov                 byte ptr [eax + edi], 0
            //   42                   | inc                 edx
            //   89550c               | mov                 dword ptr [ebp + 0xc], edx
            //   3b55dc               | cmp                 edx, dword ptr [ebp - 0x24]
            //   0f8c7affffff         | jl                  0xffffff80

        $sequence_15 = { 3bc1 a1???????? 897c240c 0f8380000000 }
            // n = 4, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   a1????????           |                     
            //   897c240c             | mov                 dword ptr [esp + 0xc], edi
            //   0f8380000000         | jae                 0x86

    condition:
        7 of them and filesize < 462848
}