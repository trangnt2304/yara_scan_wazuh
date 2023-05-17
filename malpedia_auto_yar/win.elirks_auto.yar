rule win_elirks_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.elirks."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.elirks"
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
        $sequence_0 = { ffd7 8bf8 e8???????? 6800040000 56 ff15???????? }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     
            //   6800040000           | push                0x400
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_1 = { 80780161 0f85be010000 8a4802 80f920 740e 80f90d 7409 }
            // n = 7, score = 100
            //   80780161             | cmp                 byte ptr [eax + 1], 0x61
            //   0f85be010000         | jne                 0x1c4
            //   8a4802               | mov                 cl, byte ptr [eax + 2]
            //   80f920               | cmp                 cl, 0x20
            //   740e                 | je                  0x10
            //   80f90d               | cmp                 cl, 0xd
            //   7409                 | je                  0xb

        $sequence_2 = { e8???????? 894608 eb02 33f6 8d442420 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi
            //   8d442420             | lea                 eax, [esp + 0x20]

        $sequence_3 = { 8b742408 8b442408 3d01000080 7414 8b4c240c 50 }
            // n = 6, score = 100
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   3d01000080           | cmp                 eax, 0x80000001
            //   7414                 | je                  0x16
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   50                   | push                eax

        $sequence_4 = { 81c440020000 c3 8bc7 5f }
            // n = 4, score = 100
            //   81c440020000         | add                 esp, 0x240
            //   c3                   | ret                 
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi

        $sequence_5 = { 898604600000 b801000000 898600600000 898608600000 b800600000 }
            // n = 5, score = 100
            //   898604600000         | mov                 dword ptr [esi + 0x6004], eax
            //   b801000000           | mov                 eax, 1
            //   898600600000         | mov                 dword ptr [esi + 0x6000], eax
            //   898608600000         | mov                 dword ptr [esi + 0x6008], eax
            //   b800600000           | mov                 eax, 0x6000

        $sequence_6 = { 8b542428 8b742424 890a 894204 83c608 83c208 836c240c01 }
            // n = 7, score = 100
            //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
            //   8b742424             | mov                 esi, dword ptr [esp + 0x24]
            //   890a                 | mov                 dword ptr [edx], ecx
            //   894204               | mov                 dword ptr [edx + 4], eax
            //   83c608               | add                 esi, 8
            //   83c208               | add                 edx, 8
            //   836c240c01           | sub                 dword ptr [esp + 0xc], 1

        $sequence_7 = { 50 56 c744241800000000 ff15???????? 85c0 7440 8b442410 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   56                   | push                esi
            //   c744241800000000     | mov                 dword ptr [esp + 0x18], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7440                 | je                  0x42
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]

        $sequence_8 = { 8d8c242c030000 51 bf???????? e8???????? }
            // n = 4, score = 100
            //   8d8c242c030000       | lea                 ecx, [esp + 0x32c]
            //   51                   | push                ecx
            //   bf????????           |                     
            //   e8????????           |                     

        $sequence_9 = { 898600600000 898608600000 6800100000 8d842430020000 50 }
            // n = 5, score = 100
            //   898600600000         | mov                 dword ptr [esi + 0x6000], eax
            //   898608600000         | mov                 dword ptr [esi + 0x6008], eax
            //   6800100000           | push                0x1000
            //   8d842430020000       | lea                 eax, [esp + 0x230]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 81920
}