rule win_wmighost_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.wmighost."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wmighost"
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
        $sequence_0 = { 33d2 8a15???????? 33ca 8b45f8 }
            // n = 4, score = 100
            //   33d2                 | xor                 edx, edx
            //   8a15????????         |                     
            //   33ca                 | xor                 ecx, edx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_1 = { 8d959cfeffff 52 ff15???????? 83c404 8d858cd6ffff 50 8d8d9cfeffff }
            // n = 7, score = 100
            //   8d959cfeffff         | lea                 edx, [ebp - 0x164]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   8d858cd6ffff         | lea                 eax, [ebp - 0x2974]
            //   50                   | push                eax
            //   8d8d9cfeffff         | lea                 ecx, [ebp - 0x164]

        $sequence_2 = { 8bc8 e8???????? 6aff 8d4de8 e8???????? 8bc8 }
            // n = 6, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   6aff                 | push                -1
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_3 = { 66c7858cfeffffd607 8d85f0feffff 50 8d8d8cfeffff 51 }
            // n = 5, score = 100
            //   66c7858cfeffffd607     | mov    word ptr [ebp - 0x174], 0x7d6
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax
            //   8d8d8cfeffff         | lea                 ecx, [ebp - 0x174]
            //   51                   | push                ecx

        $sequence_4 = { 83c404 5d c3 55 8bec b9???????? ff15???????? }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b9????????           |                     
            //   ff15????????         |                     

        $sequence_5 = { 51 68???????? 8b95f8feffff 52 ff15???????? 83c410 8b85f8feffff }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   68????????           |                     
            //   8b95f8feffff         | mov                 edx, dword ptr [ebp - 0x108]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83c410               | add                 esp, 0x10
            //   8b85f8feffff         | mov                 eax, dword ptr [ebp - 0x108]

        $sequence_6 = { 8b550c 52 6800280000 8d858cd6ffff }
            // n = 4, score = 100
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   52                   | push                edx
            //   6800280000           | push                0x2800
            //   8d858cd6ffff         | lea                 eax, [ebp - 0x2974]

        $sequence_7 = { 51 e8???????? c745fcffffffff 8d4d08 e8???????? 8b4df4 64890d00000000 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_8 = { ff15???????? 83c404 8985f8feffff 6804010000 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4
            //   8985f8feffff         | mov                 dword ptr [ebp - 0x108], eax
            //   6804010000           | push                0x104

        $sequence_9 = { 8d459c 50 8d4db0 51 6a00 6a00 }
            // n = 6, score = 100
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax
            //   8d4db0               | lea                 ecx, [ebp - 0x50]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 49152
}