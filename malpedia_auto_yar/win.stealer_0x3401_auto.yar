rule win_stealer_0x3401_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.stealer_0x3401."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stealer_0x3401"
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
        $sequence_0 = { 68???????? 8bd0 c645fc03 8d4dd8 e8???????? 83c408 6aff }
            // n = 7, score = 100
            //   68????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6aff                 | push                -1

        $sequence_1 = { 6aff 8d45a0 c7459c00000000 50 6a02 68???????? 6a00 }
            // n = 7, score = 100
            //   6aff                 | push                -1
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   c7459c00000000       | mov                 dword ptr [ebp - 0x64], 0
            //   50                   | push                eax
            //   6a02                 | push                2
            //   68????????           |                     
            //   6a00                 | push                0

        $sequence_2 = { 68???????? 8d4dc0 e8???????? eb3c }
            // n = 4, score = 100
            //   68????????           |                     
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]
            //   e8????????           |                     
            //   eb3c                 | jmp                 0x3e

        $sequence_3 = { c644242400 803b00 7504 33c9 eb0e 8bcb 8d5101 }
            // n = 7, score = 100
            //   c644242400           | mov                 byte ptr [esp + 0x24], 0
            //   803b00               | cmp                 byte ptr [ebx], 0
            //   7504                 | jne                 6
            //   33c9                 | xor                 ecx, ecx
            //   eb0e                 | jmp                 0x10
            //   8bcb                 | mov                 ecx, ebx
            //   8d5101               | lea                 edx, [ecx + 1]

        $sequence_4 = { 8d85587dffff 83c418 c7856c7dffff00000000 50 8d856c7dffff }
            // n = 5, score = 100
            //   8d85587dffff         | lea                 eax, [ebp - 0x82a8]
            //   83c418               | add                 esp, 0x18
            //   c7856c7dffff00000000     | mov    dword ptr [ebp - 0x8294], 0
            //   50                   | push                eax
            //   8d856c7dffff         | lea                 eax, [ebp - 0x8294]

        $sequence_5 = { eb33 8b7dd0 8b45e4 8b4de8 8b0485c8710210 f644082840 7409 }
            // n = 7, score = 100
            //   eb33                 | jmp                 0x35
            //   8b7dd0               | mov                 edi, dword ptr [ebp - 0x30]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b0485c8710210       | mov                 eax, dword ptr [eax*4 + 0x100271c8]
            //   f644082840           | test                byte ptr [eax + ecx + 0x28], 0x40
            //   7409                 | je                  0xb

        $sequence_6 = { 83e4f8 83ec24 a1???????? 33c4 89442420 0fb7451c 0fb75514 }
            // n = 7, score = 100
            //   83e4f8               | and                 esp, 0xfffffff8
            //   83ec24               | sub                 esp, 0x24
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   0fb7451c             | movzx               eax, word ptr [ebp + 0x1c]
            //   0fb75514             | movzx               edx, word ptr [ebp + 0x14]

        $sequence_7 = { 56 53 e8???????? 83c410 c74424280f000000 c744242400000000 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   c74424280f000000     | mov                 dword ptr [esp + 0x28], 0xf
            //   c744242400000000     | mov                 dword ptr [esp + 0x24], 0

        $sequence_8 = { 89442424 8b442420 50 6a00 }
            // n = 4, score = 100
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_9 = { ff15???????? 8bf0 85f6 0f848c010000 83bdccfbffff00 0f8496010000 8b8dc8fbffff }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   0f848c010000         | je                  0x192
            //   83bdccfbffff00       | cmp                 dword ptr [ebp - 0x434], 0
            //   0f8496010000         | je                  0x19c
            //   8b8dc8fbffff         | mov                 ecx, dword ptr [ebp - 0x438]

    condition:
        7 of them and filesize < 357376
}