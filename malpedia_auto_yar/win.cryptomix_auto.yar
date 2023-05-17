rule win_cryptomix_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.cryptomix."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptomix"
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
        $sequence_0 = { 8bec 686a85139f 6a06 e8???????? 59 59 ff7518 }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   686a85139f           | push                0x9f13856a
            //   6a06                 | push                6
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   ff7518               | push                dword ptr [ebp + 0x18]

        $sequence_1 = { 6a01 6800000080 50 ffd6 83f8ff 7403 50 }
            // n = 7, score = 200
            //   6a01                 | push                1
            //   6800000080           | push                0x80000000
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   83f8ff               | cmp                 eax, -1
            //   7403                 | je                  5
            //   50                   | push                eax

        $sequence_2 = { ffd6 85c0 0f8563010000 68???????? 8d85c4f9ffff 50 }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   0f8563010000         | jne                 0x169
            //   68????????           |                     
            //   8d85c4f9ffff         | lea                 eax, [ebp - 0x63c]
            //   50                   | push                eax

        $sequence_3 = { 0fb70a 6685c9 75ed 50 8d85ecfbffff 68???????? 50 }
            // n = 7, score = 200
            //   0fb70a               | movzx               ecx, word ptr [edx]
            //   6685c9               | test                cx, cx
            //   75ed                 | jne                 0xffffffef
            //   50                   | push                eax
            //   8d85ecfbffff         | lea                 eax, [ebp - 0x414]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_4 = { 8945f4 eb17 57 e8???????? 68bdb5b88f 6a08 }
            // n = 6, score = 200
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   eb17                 | jmp                 0x19
            //   57                   | push                edi
            //   e8????????           |                     
            //   68bdb5b88f           | push                0x8fb8b5bd
            //   6a08                 | push                8

        $sequence_5 = { 53 bf01000080 57 ffd0 85c0 7531 8b45fc }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   bf01000080           | mov                 edi, 0x80000001
            //   57                   | push                edi
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7531                 | jne                 0x33
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_6 = { 3d41e43038 0f85f0000000 b801000000 8b4dfc 33cd e8???????? 8be5 }
            // n = 7, score = 200
            //   3d41e43038           | cmp                 eax, 0x3830e441
            //   0f85f0000000         | jne                 0xf6
            //   b801000000           | mov                 eax, 1
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp

        $sequence_7 = { 740c 8bc8 a3???????? e8???????? 53 }
            // n = 5, score = 200
            //   740c                 | je                  0xe
            //   8bc8                 | mov                 ecx, eax
            //   a3????????           |                     
            //   e8????????           |                     
            //   53                   | push                ebx

        $sequence_8 = { 50 ffd7 bfc9f0f081 57 53 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   bfc9f0f081           | mov                 edi, 0x81f0f0c9
            //   57                   | push                edi
            //   53                   | push                ebx

        $sequence_9 = { 6a00 6a19 56 ffd0 be2c819712 85c0 7523 }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a19                 | push                0x19
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   be2c819712           | mov                 esi, 0x1297812c
            //   85c0                 | test                eax, eax
            //   7523                 | jne                 0x25

        $sequence_10 = { 50 ffd6 85c0 0f856d010000 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   0f856d010000         | jne                 0x173

        $sequence_11 = { f30f7e0e 83e908 8d7608 660fd60f 8d7f08 8b048d48134000 }
            // n = 6, score = 200
            //   f30f7e0e             | movq                xmm1, qword ptr [esi]
            //   83e908               | sub                 ecx, 8
            //   8d7608               | lea                 esi, [esi + 8]
            //   660fd60f             | movq                qword ptr [edi], xmm1
            //   8d7f08               | lea                 edi, [edi + 8]
            //   8b048d48134000       | mov                 eax, dword ptr [ecx*4 + 0x401348]

        $sequence_12 = { 83fa12 7406 42 48 85c0 7fea 8bc1 }
            // n = 7, score = 200
            //   83fa12               | cmp                 edx, 0x12
            //   7406                 | je                  8
            //   42                   | inc                 edx
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   7fea                 | jg                  0xffffffec
            //   8bc1                 | mov                 eax, ecx

        $sequence_13 = { 8945fc 8b4508 53 56 57 8bf1 6a01 }
            // n = 7, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bf1                 | mov                 esi, ecx
            //   6a01                 | push                1

        $sequence_14 = { 56 8bb5e8feffff 83fe05 750d }
            // n = 4, score = 200
            //   56                   | push                esi
            //   8bb5e8feffff         | mov                 esi, dword ptr [ebp - 0x118]
            //   83fe05               | cmp                 esi, 5
            //   750d                 | jne                 0xf

        $sequence_15 = { 51 57 57 6a06 57 }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   57                   | push                edi
            //   57                   | push                edi
            //   6a06                 | push                6
            //   57                   | push                edi

    condition:
        7 of them and filesize < 188416
}