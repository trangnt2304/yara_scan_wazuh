rule win_wipbot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.wipbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wipbot"
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
        $sequence_0 = { c68424850000002e c68424860000007d 31c0 c684248700000060 c68424880000006a c684248900000079 c684248a0000007d }
            // n = 7, score = 100
            //   c68424850000002e     | mov                 byte ptr [esp + 0x85], 0x2e
            //   c68424860000007d     | mov                 byte ptr [esp + 0x86], 0x7d
            //   31c0                 | xor                 eax, eax
            //   c684248700000060     | mov                 byte ptr [esp + 0x87], 0x60
            //   c68424880000006a     | mov                 byte ptr [esp + 0x88], 0x6a
            //   c684248900000079     | mov                 byte ptr [esp + 0x89], 0x79
            //   c684248a0000007d     | mov                 byte ptr [esp + 0x8a], 0x7d

        $sequence_1 = { 83f22e 83f835 8811 75ee ba55c4e6f5 b83272115b }
            // n = 6, score = 100
            //   83f22e               | xor                 edx, 0x2e
            //   83f835               | cmp                 eax, 0x35
            //   8811                 | mov                 byte ptr [ecx], dl
            //   75ee                 | jne                 0xfffffff0
            //   ba55c4e6f5           | mov                 edx, 0xf5e6c455
            //   b83272115b           | mov                 eax, 0x5b117232

        $sequence_2 = { bafe20affb b98a758b1f e8???????? 48 85c0 }
            // n = 5, score = 100
            //   bafe20affb           | mov                 edx, 0xfbaf20fe
            //   b98a758b1f           | mov                 ecx, 0x1f8b758a
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax

        $sequence_3 = { 89c7 7504 31c0 eb72 4c 8b03 4d }
            // n = 7, score = 100
            //   89c7                 | mov                 edi, eax
            //   7504                 | jne                 6
            //   31c0                 | xor                 eax, eax
            //   eb72                 | jmp                 0x74
            //   4c                   | dec                 esp
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   4d                   | dec                 ebp

        $sequence_4 = { c685d0feffff69 c685d1feffff63 c685d2feffff7e c685d3feffff5d c685d4feffff6d c685d5feffff7b }
            // n = 6, score = 100
            //   c685d0feffff69       | mov                 byte ptr [ebp - 0x130], 0x69
            //   c685d1feffff63       | mov                 byte ptr [ebp - 0x12f], 0x63
            //   c685d2feffff7e       | mov                 byte ptr [ebp - 0x12e], 0x7e
            //   c685d3feffff5d       | mov                 byte ptr [ebp - 0x12d], 0x5d
            //   c685d4feffff6d       | mov                 byte ptr [ebp - 0x12c], 0x6d
            //   c685d5feffff7b       | mov                 byte ptr [ebp - 0x12b], 0x7b

        $sequence_5 = { 85c0 741a 48 8b4018 48 85c0 7411 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   741a                 | je                  0x1c
            //   48                   | dec                 eax
            //   8b4018               | mov                 eax, dword ptr [eax + 0x18]
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   7411                 | je                  0x13

        $sequence_6 = { 74c2 8d55dc 89542414 8b55d4 }
            // n = 4, score = 100
            //   74c2                 | je                  0xffffffc4
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   8b55d4               | mov                 edx, dword ptr [ebp - 0x2c]

        $sequence_7 = { ba35c7e45c 6689442430 b98a758b1f ffc0 48 c744242800000000 6689442432 }
            // n = 7, score = 100
            //   ba35c7e45c           | mov                 edx, 0x5ce4c735
            //   6689442430           | mov                 word ptr [esp + 0x30], ax
            //   b98a758b1f           | mov                 ecx, 0x1f8b758a
            //   ffc0                 | inc                 eax
            //   48                   | dec                 eax
            //   c744242800000000     | mov                 dword ptr [esp + 0x28], 0
            //   6689442432           | mov                 word ptr [esp + 0x32], ax

        $sequence_8 = { 48 89442440 48 8d442470 48 8d942486000000 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   89442440             | mov                 dword ptr [esp + 0x40], eax
            //   48                   | dec                 eax
            //   8d442470             | lea                 eax, [esp + 0x70]
            //   48                   | dec                 eax
            //   8d942486000000       | lea                 edx, [esp + 0x86]
            //   48                   | dec                 eax

        $sequence_9 = { 48 8d8c24a1020000 88c2 48 01c1 48 ffc0 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8d8c24a1020000       | lea                 ecx, [esp + 0x2a1]
            //   88c2                 | mov                 dl, al
            //   48                   | dec                 eax
            //   01c1                 | add                 ecx, eax
            //   48                   | dec                 eax
            //   ffc0                 | inc                 eax

    condition:
        7 of them and filesize < 253952
}