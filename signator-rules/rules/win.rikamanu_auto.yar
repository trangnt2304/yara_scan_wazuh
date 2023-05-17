rule win_rikamanu_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.rikamanu."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rikamanu"
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
        $sequence_0 = { e8???????? 6a14 ff15???????? a801 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   6a14                 | push                0x14
            //   ff15????????         |                     
            //   a801                 | test                al, 1

        $sequence_1 = { 50 ff15???????? 8b35???????? 3d80969800 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   3d80969800           | cmp                 eax, 0x989680

        $sequence_2 = { ff15???????? 55 89442430 ff15???????? 896c2434 c744243848724000 89442430 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   55                   | push                ebp
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   ff15????????         |                     
            //   896c2434             | mov                 dword ptr [esp + 0x34], ebp
            //   c744243848724000     | mov                 dword ptr [esp + 0x38], 0x407248
            //   89442430             | mov                 dword ptr [esp + 0x30], eax

        $sequence_3 = { 8945e4 3d00010000 7d10 8a8c181d010000 888808972400 40 ebe6 }
            // n = 7, score = 100
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   3d00010000           | cmp                 eax, 0x100
            //   7d10                 | jge                 0x12
            //   8a8c181d010000       | mov                 cl, byte ptr [eax + ebx + 0x11d]
            //   888808972400         | mov                 byte ptr [eax + 0x249708], cl
            //   40                   | inc                 eax
            //   ebe6                 | jmp                 0xffffffe8

        $sequence_4 = { 7419 0fb6da f683a1a7400004 7406 8816 46 40 }
            // n = 7, score = 100
            //   7419                 | je                  0x1b
            //   0fb6da               | movzx               ebx, dl
            //   f683a1a7400004       | test                byte ptr [ebx + 0x40a7a1], 4
            //   7406                 | je                  8
            //   8816                 | mov                 byte ptr [esi], dl
            //   46                   | inc                 esi
            //   40                   | inc                 eax

        $sequence_5 = { 8bec 8b4508 33c9 3b04cd00992400 7413 41 }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   33c9                 | xor                 ecx, ecx
            //   3b04cd00992400       | cmp                 eax, dword ptr [ecx*8 + 0x249900]
            //   7413                 | je                  0x15
            //   41                   | inc                 ecx

        $sequence_6 = { 83f841 720e 83f85a 7709 ff750c ff15???????? ff750c }
            // n = 7, score = 100
            //   83f841               | cmp                 eax, 0x41
            //   720e                 | jb                  0x10
            //   83f85a               | cmp                 eax, 0x5a
            //   7709                 | ja                  0xb
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff15????????         |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]

        $sequence_7 = { f7d1 49 51 68???????? 55 ffd3 bf???????? }
            // n = 7, score = 100
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   51                   | push                ecx
            //   68????????           |                     
            //   55                   | push                ebp
            //   ffd3                 | call                ebx
            //   bf????????           |                     

        $sequence_8 = { 0fb6d2 f682a1a7400004 740c ff01 85f6 7406 8a10 }
            // n = 7, score = 100
            //   0fb6d2               | movzx               edx, dl
            //   f682a1a7400004       | test                byte ptr [edx + 0x40a7a1], 4
            //   740c                 | je                  0xe
            //   ff01                 | inc                 dword ptr [ecx]
            //   85f6                 | test                esi, esi
            //   7406                 | je                  8
            //   8a10                 | mov                 dl, byte ptr [eax]

        $sequence_9 = { 68???????? 40 50 ff15???????? a3???????? }
            // n = 5, score = 100
            //   68????????           |                     
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_10 = { e8???????? 33db 899de8fdffff 899df0fdffff ff15???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   899de8fdffff         | mov                 dword ptr [ebp - 0x218], ebx
            //   899df0fdffff         | mov                 dword ptr [ebp - 0x210], ebx
            //   ff15????????         |                     

        $sequence_11 = { 83c42c 5f eb26 8d4508 8db62c724000 }
            // n = 5, score = 100
            //   83c42c               | add                 esp, 0x2c
            //   5f                   | pop                 edi
            //   eb26                 | jmp                 0x28
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8db62c724000         | lea                 esi, [esi + 0x40722c]

        $sequence_12 = { 8945c4 0f87e9060000 ff2485ea1f4000 33c0 834df8ff }
            // n = 5, score = 100
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   0f87e9060000         | ja                  0x6ef
            //   ff2485ea1f4000       | jmp                 dword ptr [eax*4 + 0x401fea]
            //   33c0                 | xor                 eax, eax
            //   834df8ff             | or                  dword ptr [ebp - 8], 0xffffffff

        $sequence_13 = { 8bca 8d942434020000 83e103 f3a4 b982000000 8dbc2434020000 f3ab }
            // n = 7, score = 100
            //   8bca                 | mov                 ecx, edx
            //   8d942434020000       | lea                 edx, [esp + 0x234]
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   b982000000           | mov                 ecx, 0x82
            //   8dbc2434020000       | lea                 edi, [esp + 0x234]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_14 = { 8dbdd4feffff 33db f3ab bf007f0000 c785d0feffff03000000 57 }
            // n = 6, score = 100
            //   8dbdd4feffff         | lea                 edi, [ebp - 0x12c]
            //   33db                 | xor                 ebx, ebx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   bf007f0000           | mov                 edi, 0x7f00
            //   c785d0feffff03000000     | mov    dword ptr [ebp - 0x130], 3
            //   57                   | push                edi

        $sequence_15 = { 53 53 53 8d95f4fdffff 52 53 50 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   8d95f4fdffff         | lea                 edx, [ebp - 0x20c]
            //   52                   | push                edx
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_16 = { 51 6a01 56 ff15???????? 5e c21000 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   6a01                 | push                1
            //   56                   | push                esi
            //   ff15????????         |                     
            //   5e                   | pop                 esi
            //   c21000               | ret                 0x10

        $sequence_17 = { 50 8d8de4fdffff 51 e8???????? 8b8de4fdffff }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d8de4fdffff         | lea                 ecx, [ebp - 0x21c]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b8de4fdffff         | mov                 ecx, dword ptr [ebp - 0x21c]

        $sequence_18 = { 8dbdf4fdffff 2bc2 4f 8a4f01 47 3acb 75f8 }
            // n = 7, score = 100
            //   8dbdf4fdffff         | lea                 edi, [ebp - 0x20c]
            //   2bc2                 | sub                 eax, edx
            //   4f                   | dec                 edi
            //   8a4f01               | mov                 cl, byte ptr [edi + 1]
            //   47                   | inc                 edi
            //   3acb                 | cmp                 cl, bl
            //   75f8                 | jne                 0xfffffffa

        $sequence_19 = { 83f811 7522 0fb74e12 6685c9 750c 391d???????? }
            // n = 6, score = 100
            //   83f811               | cmp                 eax, 0x11
            //   7522                 | jne                 0x24
            //   0fb74e12             | movzx               ecx, word ptr [esi + 0x12]
            //   6685c9               | test                cx, cx
            //   750c                 | jne                 0xe
            //   391d????????         |                     

        $sequence_20 = { 33c9 25ffff0000 668b0d???????? 50 }
            // n = 4, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   25ffff0000           | and                 eax, 0xffff
            //   668b0d????????       |                     
            //   50                   | push                eax

        $sequence_21 = { 83e103 50 f3a4 ff15???????? 8b4c2428 8b542426 8b442424 }
            // n = 7, score = 100
            //   83e103               | and                 ecx, 3
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   ff15????????         |                     
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   8b542426             | mov                 edx, dword ptr [esp + 0x26]
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]

        $sequence_22 = { c1f805 c1e106 8b0485383f4100 f644080401 7405 8b0408 5d }
            // n = 7, score = 100
            //   c1f805               | sar                 eax, 5
            //   c1e106               | shl                 ecx, 6
            //   8b0485383f4100       | mov                 eax, dword ptr [eax*4 + 0x413f38]
            //   f644080401           | test                byte ptr [eax + ecx + 4], 1
            //   7405                 | je                  7
            //   8b0408               | mov                 eax, dword ptr [eax + ecx]
            //   5d                   | pop                 ebp

        $sequence_23 = { 00dc 3a4000 003b 40 0023 d18a0688078a 46 }
            // n = 7, score = 100
            //   00dc                 | add                 ah, bl
            //   3a4000               | cmp                 al, byte ptr [eax]
            //   003b                 | add                 byte ptr [ebx], bh
            //   40                   | inc                 eax
            //   0023                 | add                 byte ptr [ebx], ah
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi

        $sequence_24 = { 833cf5602a410000 7513 56 e8???????? 59 }
            // n = 5, score = 100
            //   833cf5602a410000     | cmp                 dword ptr [esi*8 + 0x412a60], 0
            //   7513                 | jne                 0x15
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_25 = { 8d85f8feffff 50 51 c705????????20010000 c705????????02000000 }
            // n = 5, score = 100
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   c705????????20010000     |     
            //   c705????????02000000     |     

        $sequence_26 = { 8dbc2441050000 889c2440050000 f3ab 66ab aa }
            // n = 5, score = 100
            //   8dbc2441050000       | lea                 edi, [esp + 0x541]
            //   889c2440050000       | mov                 byte ptr [esp + 0x540], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_27 = { 8d7e01 3bfb 7ed0 83c8ff eb07 8b04f5a4f54000 }
            // n = 6, score = 100
            //   8d7e01               | lea                 edi, [esi + 1]
            //   3bfb                 | cmp                 edi, ebx
            //   7ed0                 | jle                 0xffffffd2
            //   83c8ff               | or                  eax, 0xffffffff
            //   eb07                 | jmp                 9
            //   8b04f5a4f54000       | mov                 eax, dword ptr [esi*8 + 0x40f5a4]

        $sequence_28 = { 8d942434020000 83e103 53 f3a4 8d7c2430 }
            // n = 5, score = 100
            //   8d942434020000       | lea                 edx, [esp + 0x234]
            //   83e103               | and                 ecx, 3
            //   53                   | push                ebx
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d7c2430             | lea                 edi, [esp + 0x30]

        $sequence_29 = { ff15???????? 85c0 74d2 a1???????? 85c0 74c9 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   74d2                 | je                  0xffffffd4
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   74c9                 | je                  0xffffffcb

    condition:
        7 of them and filesize < 212992
}