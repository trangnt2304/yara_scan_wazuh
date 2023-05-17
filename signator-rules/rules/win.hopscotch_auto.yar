rule win_hopscotch_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.hopscotch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hopscotch"
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
        $sequence_0 = { e8???????? 83c408 8d9424a8020000 52 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d9424a8020000       | lea                 edx, [esp + 0x2a8]
            //   52                   | push                edx

        $sequence_1 = { 894c2438 c744241800000000 c744242803000000 c744243000000000 e8???????? 8bf0 85f6 }
            // n = 7, score = 100
            //   894c2438             | mov                 dword ptr [esp + 0x38], ecx
            //   c744241800000000     | mov                 dword ptr [esp + 0x18], 0
            //   c744242803000000     | mov                 dword ptr [esp + 0x28], 3
            //   c744243000000000     | mov                 dword ptr [esp + 0x30], 0
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi

        $sequence_2 = { 83c40c 8b0d???????? 8d442410 6a00 50 56 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8b0d????????         |                     
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_3 = { 83c40c bd01000000 8b442410 85c0 7406 }
            // n = 5, score = 100
            //   83c40c               | add                 esp, 0xc
            //   bd01000000           | mov                 ebp, 1
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   85c0                 | test                eax, eax
            //   7406                 | je                  8

        $sequence_4 = { e8???????? 83c408 68???????? e8???????? 8d4c2478 6801010000 51 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   68????????           |                     
            //   e8????????           |                     
            //   8d4c2478             | lea                 ecx, [esp + 0x78]
            //   6801010000           | push                0x101
            //   51                   | push                ecx

        $sequence_5 = { 8bb42474080000 52 56 c744243001000000 }
            // n = 4, score = 100
            //   8bb42474080000       | mov                 esi, dword ptr [esp + 0x874]
            //   52                   | push                edx
            //   56                   | push                esi
            //   c744243001000000     | mov                 dword ptr [esp + 0x30], 1

        $sequence_6 = { 68???????? e8???????? 83c408 8d9424a8020000 }
            // n = 4, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d9424a8020000       | lea                 edx, [esp + 0x2a8]

        $sequence_7 = { 6a00 8d9424b4000000 6a00 8d442424 52 50 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   8d9424b4000000       | lea                 edx, [esp + 0xb4]
            //   6a00                 | push                0
            //   8d442424             | lea                 eax, [esp + 0x24]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_8 = { 51 e8???????? 56 53 56 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   56                   | push                esi
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_9 = { 51 ffd7 8b16 52 ffd3 8b4604 85c0 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 1143808
}