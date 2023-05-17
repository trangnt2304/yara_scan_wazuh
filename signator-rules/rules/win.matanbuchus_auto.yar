rule win_matanbuchus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.matanbuchus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matanbuchus"
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
        $sequence_0 = { 8d9401f8000000 52 e8???????? 837dec40 }
            // n = 4, score = 400
            //   8d9401f8000000       | lea                 edx, [ecx + eax + 0xf8]
            //   52                   | push                edx
            //   e8????????           |                     
            //   837dec40             | cmp                 dword ptr [ebp - 0x14], 0x40

        $sequence_1 = { 742e 8b4508 8945fc 8b4d10 894df8 8b5510 }
            // n = 6, score = 400
            //   742e                 | je                  0x30
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]

        $sequence_2 = { 8945f0 8b4df0 3b4de4 736d 8b55f0 8b45f4 0fb74c5008 }
            // n = 7, score = 400
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   3b4de4               | cmp                 ecx, dword ptr [ebp - 0x1c]
            //   736d                 | jae                 0x6f
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   0fb74c5008           | movzx               ecx, word ptr [eax + edx*2 + 8]

        $sequence_3 = { 8b450c 50 8b4d08 51 683afd800e }
            // n = 5, score = 400
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   51                   | push                ecx
            //   683afd800e           | push                0xe80fd3a

        $sequence_4 = { 52 50 e8???????? 8bc8 8b4514 8b5518 }
            // n = 6, score = 400
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]

        $sequence_5 = { 41 66894df8 0fb755fc 85d2 7502 ebb4 0fb745fc }
            // n = 7, score = 400
            //   41                   | inc                 ecx
            //   66894df8             | mov                 word ptr [ebp - 8], cx
            //   0fb755fc             | movzx               edx, word ptr [ebp - 4]
            //   85d2                 | test                edx, edx
            //   7502                 | jne                 4
            //   ebb4                 | jmp                 0xffffffb6
            //   0fb745fc             | movzx               eax, word ptr [ebp - 4]

        $sequence_6 = { 8b45ec 0fb60c10 334df8 894df8 6955f895e9d15b }
            // n = 5, score = 400
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   0fb60c10             | movzx               ecx, byte ptr [eax + edx]
            //   334df8               | xor                 ecx, dword ptr [ebp - 8]
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   6955f895e9d15b       | imul                edx, dword ptr [ebp - 8], 0x5bd1e995

        $sequence_7 = { 51 8b55f0 52 6b45f828 8b4dfc 038c0534fdffff }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   52                   | push                edx
            //   6b45f828             | imul                eax, dword ptr [ebp - 8], 0x28
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   038c0534fdffff       | add                 ecx, dword ptr [ebp + eax - 0x2cc]

        $sequence_8 = { 8b550c 3b55e0 750f 8b45f8 }
            // n = 4, score = 400
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   3b55e0               | cmp                 edx, dword ptr [ebp - 0x20]
            //   750f                 | jne                 0x11
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_9 = { 3b4a14 7321 0fb745fc 8b4ddc }
            // n = 4, score = 400
            //   3b4a14               | cmp                 ecx, dword ptr [edx + 0x14]
            //   7321                 | jae                 0x23
            //   0fb745fc             | movzx               eax, word ptr [ebp - 4]
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]

    condition:
        7 of them and filesize < 2056192
}