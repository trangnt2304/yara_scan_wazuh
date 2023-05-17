rule win_scanpos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.scanpos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scanpos"
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
        $sequence_0 = { e8???????? 33ff c745fcffffffff 83bde0feffff10 720f }
            // n = 5, score = 200
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   83bde0feffff10       | cmp                 dword ptr [ebp - 0x120], 0x10
            //   720f                 | jb                  0x11

        $sequence_1 = { 2bc2 3bc8 761f 8bd0 d1ea 83cfff }
            // n = 6, score = 200
            //   2bc2                 | sub                 eax, edx
            //   3bc8                 | cmp                 ecx, eax
            //   761f                 | jbe                 0x21
            //   8bd0                 | mov                 edx, eax
            //   d1ea                 | shr                 edx, 1
            //   83cfff               | or                  edi, 0xffffffff

        $sequence_2 = { 8bd0 8b06 8b4004 8b4c3020 8b443024 33ff 8955e8 }
            // n = 7, score = 200
            //   8bd0                 | mov                 edx, eax
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   8b4c3020             | mov                 ecx, dword ptr [eax + esi + 0x20]
            //   8b443024             | mov                 eax, dword ptr [eax + esi + 0x24]
            //   33ff                 | xor                 edi, edi
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx

        $sequence_3 = { 7303 8d75d4 8b45b0 50 53 8d4db8 }
            // n = 6, score = 200
            //   7303                 | jae                 5
            //   8d75d4               | lea                 esi, [ebp - 0x2c]
            //   8b45b0               | mov                 eax, dword ptr [ebp - 0x50]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   8d4db8               | lea                 ecx, [ebp - 0x48]

        $sequence_4 = { 51 8bde e8???????? c745fc00000000 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8bde                 | mov                 ebx, esi
            //   e8????????           |                     
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0

        $sequence_5 = { 8b45d4 8b08 8b5104 8b4c0238 85c9 7407 8b01 }
            // n = 7, score = 200
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   8b4c0238             | mov                 ecx, dword ptr [edx + eax + 0x38]
            //   85c9                 | test                ecx, ecx
            //   7407                 | je                  9
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_6 = { 7514 c1e902 83e203 83f908 7229 f3a5 ff249540554000 }
            // n = 7, score = 200
            //   7514                 | jne                 0x16
            //   c1e902               | shr                 ecx, 2
            //   83e203               | and                 edx, 3
            //   83f908               | cmp                 ecx, 8
            //   7229                 | jb                  0x2b
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff249540554000       | jmp                 dword ptr [edx*4 + 0x405540]

        $sequence_7 = { 7408 3c44 0f8530020000 8d47f0 8945ac 8a00 3c33 }
            // n = 7, score = 200
            //   7408                 | je                  0xa
            //   3c44                 | cmp                 al, 0x44
            //   0f8530020000         | jne                 0x236
            //   8d47f0               | lea                 eax, [edi - 0x10]
            //   8945ac               | mov                 dword ptr [ebp - 0x54], eax
            //   8a00                 | mov                 al, byte ptr [eax]
            //   3c33                 | cmp                 al, 0x33

        $sequence_8 = { 55 8bec 8b4508 ff34c5106b4100 ff15???????? 5d c3 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff34c5106b4100       | push                dword ptr [eax*8 + 0x416b10]
            //   ff15????????         |                     
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_9 = { c786cc000000581a4100 c786d0000000d81b4100 c786ac00000001000000 33c0 8b4dfc 5f }
            // n = 6, score = 200
            //   c786cc000000581a4100     | mov    dword ptr [esi + 0xcc], 0x411a58
            //   c786d0000000d81b4100     | mov    dword ptr [esi + 0xd0], 0x411bd8
            //   c786ac00000001000000     | mov    dword ptr [esi + 0xac], 1
            //   33c0                 | xor                 eax, eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 229376
}