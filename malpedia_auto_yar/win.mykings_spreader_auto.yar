rule win_mykings_spreader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.mykings_spreader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mykings_spreader"
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
        $sequence_0 = { 8b45e8 8b55a8 0355cc 8955e8 2b5598 e9???????? }
            // n = 6, score = 100
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8b55a8               | mov                 edx, dword ptr [ebp - 0x58]
            //   0355cc               | add                 edx, dword ptr [ebp - 0x34]
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   2b5598               | sub                 edx, dword ptr [ebp - 0x68]
            //   e9????????           |                     

        $sequence_1 = { 85db 0f84c8020000 c745f001000000 8b4508 f7d0 8b7510 85f6 }
            // n = 7, score = 100
            //   85db                 | test                ebx, ebx
            //   0f84c8020000         | je                  0x2ce
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   f7d0                 | not                 eax
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   85f6                 | test                esi, esi

        $sequence_2 = { 8b4304 8b8098000000 89430c 8b4304 899898000000 b8???????? e8???????? }
            // n = 7, score = 100
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   8b8098000000         | mov                 eax, dword ptr [eax + 0x98]
            //   89430c               | mov                 dword ptr [ebx + 0xc], eax
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   899898000000         | mov                 dword ptr [eax + 0x98], ebx
            //   b8????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 39d1 72e8 8975cc 895dd0 897dc8 894dc4 }
            // n = 6, score = 100
            //   39d1                 | cmp                 ecx, edx
            //   72e8                 | jb                  0xffffffea
            //   8975cc               | mov                 dword ptr [ebp - 0x34], esi
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi
            //   894dc4               | mov                 dword ptr [ebp - 0x3c], ecx

        $sequence_4 = { 0fb645f4 83f83a 7d06 8045f404 eb13 0fb645f4 83f82b }
            // n = 7, score = 100
            //   0fb645f4             | movzx               eax, byte ptr [ebp - 0xc]
            //   83f83a               | cmp                 eax, 0x3a
            //   7d06                 | jge                 8
            //   8045f404             | add                 byte ptr [ebp - 0xc], 4
            //   eb13                 | jmp                 0x15
            //   0fb645f4             | movzx               eax, byte ptr [ebp - 0xc]
            //   83f82b               | cmp                 eax, 0x2b

        $sequence_5 = { 0f97857bffffff 8b4de8 83c105 394d84 0f97c1 088d7bffffff 8a8d7bffffff }
            // n = 7, score = 100
            //   0f97857bffffff       | seta                byte ptr [ebp - 0x85]
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   83c105               | add                 ecx, 5
            //   394d84               | cmp                 dword ptr [ebp - 0x7c], ecx
            //   0f97c1               | seta                cl
            //   088d7bffffff         | or                  byte ptr [ebp - 0x85], cl
            //   8a8d7bffffff         | mov                 cl, byte ptr [ebp - 0x85]

        $sequence_6 = { 003f 5a 42 0008 5a 42 }
            // n = 6, score = 100
            //   003f                 | add                 byte ptr [edi], bh
            //   5a                   | pop                 edx
            //   42                   | inc                 edx
            //   0008                 | add                 byte ptr [eax], cl
            //   5a                   | pop                 edx
            //   42                   | inc                 edx

        $sequence_7 = { 88450b 8d3c8da02e4100 c1e603 8b0f 80650b48 88443104 7578 }
            // n = 7, score = 100
            //   88450b               | mov                 byte ptr [ebp + 0xb], al
            //   8d3c8da02e4100       | lea                 edi, [ecx*4 + 0x412ea0]
            //   c1e603               | shl                 esi, 3
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   80650b48             | and                 byte ptr [ebp + 0xb], 0x48
            //   88443104             | mov                 byte ptr [ecx + esi + 4], al
            //   7578                 | jne                 0x7a

        $sequence_8 = { 55 89e5 a1???????? 83f8ff 751e e8???????? a3???????? }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   a1????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   751e                 | jne                 0x20
            //   e8????????           |                     
            //   a3????????           |                     

        $sequence_9 = { 89bd64ffffff 8945fc 8955f8 894df4 8b75fc 8d7db4 fc }
            // n = 7, score = 100
            //   89bd64ffffff         | mov                 dword ptr [ebp - 0x9c], edi
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   8d7db4               | lea                 edi, [ebp - 0x4c]
            //   fc                   | cld                 

    condition:
        7 of them and filesize < 1581056
}