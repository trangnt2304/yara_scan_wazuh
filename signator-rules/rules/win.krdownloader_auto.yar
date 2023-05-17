rule win_krdownloader_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.krdownloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.krdownloader"
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
        $sequence_0 = { 8d95f0fbffff 52 e8???????? 83c404 50 8d85f0fbffff 50 }
            // n = 7, score = 200
            //   8d95f0fbffff         | lea                 edx, [ebp - 0x410]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   8d85f0fbffff         | lea                 eax, [ebp - 0x410]
            //   50                   | push                eax

        $sequence_1 = { 8b55fc 894238 68???????? 8b45fc 8b4834 51 ff15???????? }
            // n = 7, score = 200
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   894238               | mov                 dword ptr [edx + 0x38], eax
            //   68????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4834               | mov                 ecx, dword ptr [eax + 0x34]
            //   51                   | push                ecx
            //   ff15????????         |                     

        $sequence_2 = { c745ec00000000 c745f400000000 c745d810000000 c745e000000000 c745d000000000 c745f800000000 c745e800000000 }
            // n = 7, score = 200
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   c745f400000000       | mov                 dword ptr [ebp - 0xc], 0
            //   c745d810000000       | mov                 dword ptr [ebp - 0x28], 0x10
            //   c745e000000000       | mov                 dword ptr [ebp - 0x20], 0
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   c745e800000000       | mov                 dword ptr [ebp - 0x18], 0

        $sequence_3 = { c645f035 c645f145 c645f236 c645f346 c645f437 c645f538 }
            // n = 6, score = 200
            //   c645f035             | mov                 byte ptr [ebp - 0x10], 0x35
            //   c645f145             | mov                 byte ptr [ebp - 0xf], 0x45
            //   c645f236             | mov                 byte ptr [ebp - 0xe], 0x36
            //   c645f346             | mov                 byte ptr [ebp - 0xd], 0x46
            //   c645f437             | mov                 byte ptr [ebp - 0xc], 0x37
            //   c645f538             | mov                 byte ptr [ebp - 0xb], 0x38

        $sequence_4 = { 6a40 8d8d6cffffff 51 e8???????? 83c43c 8d956cffffff 52 }
            // n = 7, score = 200
            //   6a40                 | push                0x40
            //   8d8d6cffffff         | lea                 ecx, [ebp - 0x94]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c43c               | add                 esp, 0x3c
            //   8d956cffffff         | lea                 edx, [ebp - 0x94]
            //   52                   | push                edx

        $sequence_5 = { 51 68???????? 8b55fc 8b82540d0300 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   68????????           |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b82540d0300         | mov                 eax, dword ptr [edx + 0x30d54]

        $sequence_6 = { 894de4 8b55e4 83c204 8955d8 8b45fc }
            // n = 5, score = 200
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   83c204               | add                 edx, 4
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { 8b4dac 8b11 8955a8 eb06 8b45ac 8945a8 8b4da8 }
            // n = 7, score = 200
            //   8b4dac               | mov                 ecx, dword ptr [ebp - 0x54]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8955a8               | mov                 dword ptr [ebp - 0x58], edx
            //   eb06                 | jmp                 8
            //   8b45ac               | mov                 eax, dword ptr [ebp - 0x54]
            //   8945a8               | mov                 dword ptr [ebp - 0x58], eax
            //   8b4da8               | mov                 ecx, dword ptr [ebp - 0x58]

        $sequence_8 = { 8b450c 50 68???????? 8d8df8fbffff 51 e8???????? 83c40c }
            // n = 7, score = 200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   50                   | push                eax
            //   68????????           |                     
            //   8d8df8fbffff         | lea                 ecx, [ebp - 0x408]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_9 = { 51 8b15???????? 8b420c ffd0 8b4dfc 83b9500d030000 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   8b15????????         |                     
            //   8b420c               | mov                 eax, dword ptr [edx + 0xc]
            //   ffd0                 | call                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83b9500d030000       | cmp                 dword ptr [ecx + 0x30d50], 0

    condition:
        7 of them and filesize < 352256
}