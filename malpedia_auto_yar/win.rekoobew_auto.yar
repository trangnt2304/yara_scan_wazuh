rule win_rekoobew_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.rekoobew."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rekoobew"
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
        $sequence_0 = { e8???????? 89c2 b813000000 83fa01 7579 8b45e4 c680c0c6410000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89c2                 | mov                 edx, eax
            //   b813000000           | mov                 eax, 0x13
            //   83fa01               | cmp                 edx, 1
            //   7579                 | jne                 0x7b
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   c680c0c6410000       | mov                 byte ptr [eax + 0x41c6c0], 0

        $sequence_1 = { 0fb6d1 8b3c95e07c4000 33bb78010000 8b55ec c1ea18 }
            // n = 5, score = 100
            //   0fb6d1               | movzx               edx, cl
            //   8b3c95e07c4000       | mov                 edi, dword ptr [edx*4 + 0x407ce0]
            //   33bb78010000         | xor                 edi, dword ptr [ebx + 0x178]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   c1ea18               | shr                 edx, 0x18

        $sequence_2 = { c1ef10 81e7ff000000 330cbde0884000 894df0 8b4de0 0fb6fd 8b4df0 }
            // n = 7, score = 100
            //   c1ef10               | shr                 edi, 0x10
            //   81e7ff000000         | and                 edi, 0xff
            //   330cbde0884000       | xor                 ecx, dword ptr [edi*4 + 0x4088e0]
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   0fb6fd               | movzx               edi, ch
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_3 = { 891c24 e8???????? 891c24 e8???????? c744240840000000 c7442404???????? 891c24 }
            // n = 7, score = 100
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   c744240840000000     | mov                 dword ptr [esp + 8], 0x40
            //   c7442404????????     |                     
            //   891c24               | mov                 dword ptr [esp], ebx

        $sequence_4 = { 3c0d 745e 80f93d 0f85a0feffff 89f0 eb53 b8ffffffff }
            // n = 7, score = 100
            //   3c0d                 | cmp                 al, 0xd
            //   745e                 | je                  0x60
            //   80f93d               | cmp                 cl, 0x3d
            //   0f85a0feffff         | jne                 0xfffffea6
            //   89f0                 | mov                 eax, esi
            //   eb53                 | jmp                 0x55
            //   b8ffffffff           | mov                 eax, 0xffffffff

        $sequence_5 = { 09d7 0fb65013 09d7 0fb65012 c1e208 09d7 897de4 }
            // n = 7, score = 100
            //   09d7                 | or                  edi, edx
            //   0fb65013             | movzx               edx, byte ptr [eax + 0x13]
            //   09d7                 | or                  edi, edx
            //   0fb65012             | movzx               edx, byte ptr [eax + 0x12]
            //   c1e208               | shl                 edx, 8
            //   09d7                 | or                  edi, edx
            //   897de4               | mov                 dword ptr [ebp - 0x1c], edi

        $sequence_6 = { 331c95e0844000 89da 8b75f0 c1ee10 81e6ff000000 3314b5e0884000 8b4de4 }
            // n = 7, score = 100
            //   331c95e0844000       | xor                 ebx, dword ptr [edx*4 + 0x4084e0]
            //   89da                 | mov                 edx, ebx
            //   8b75f0               | mov                 esi, dword ptr [ebp - 0x10]
            //   c1ee10               | shr                 esi, 0x10
            //   81e6ff000000         | and                 esi, 0xff
            //   3314b5e0884000       | xor                 edx, dword ptr [esi*4 + 0x4088e0]
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]

        $sequence_7 = { 89df c1c705 01fa c1c01e 8b7db4 337dc8 }
            // n = 6, score = 100
            //   89df                 | mov                 edi, ebx
            //   c1c705               | rol                 edi, 5
            //   01fa                 | add                 edx, edi
            //   c1c01e               | rol                 eax, 0x1e
            //   8b7db4               | mov                 edi, dword ptr [ebp - 0x4c]
            //   337dc8               | xor                 edi, dword ptr [ebp - 0x38]

        $sequence_8 = { 333495e0744000 8b55e4 0fb6fe 3334bde0784000 0fb655ec 8b3c95e07c4000 33bb74010000 }
            // n = 7, score = 100
            //   333495e0744000       | xor                 esi, dword ptr [edx*4 + 0x4074e0]
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   0fb6fe               | movzx               edi, dh
            //   3334bde0784000       | xor                 esi, dword ptr [edi*4 + 0x4078e0]
            //   0fb655ec             | movzx               edx, byte ptr [ebp - 0x14]
            //   8b3c95e07c4000       | mov                 edi, dword ptr [edx*4 + 0x407ce0]
            //   33bb74010000         | xor                 edi, dword ptr [ebx + 0x174]

        $sequence_9 = { c1e718 0fb65025 c1e210 09d7 0fb64827 }
            // n = 5, score = 100
            //   c1e718               | shl                 edi, 0x18
            //   0fb65025             | movzx               edx, byte ptr [eax + 0x25]
            //   c1e210               | shl                 edx, 0x10
            //   09d7                 | or                  edi, edx
            //   0fb64827             | movzx               ecx, byte ptr [eax + 0x27]

    condition:
        7 of them and filesize < 248832
}