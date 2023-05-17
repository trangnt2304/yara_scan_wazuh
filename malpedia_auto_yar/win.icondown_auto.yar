rule win_icondown_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.icondown."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icondown"
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
        $sequence_0 = { 7404 33ff eb13 8b461c 50 ff15???????? }
            // n = 6, score = 200
            //   7404                 | je                  6
            //   33ff                 | xor                 edi, edi
            //   eb13                 | jmp                 0x15
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 8d94246c010000 aa 52 8d842470070000 68???????? }
            // n = 5, score = 200
            //   8d94246c010000       | lea                 edx, [esp + 0x16c]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   52                   | push                edx
            //   8d842470070000       | lea                 eax, [esp + 0x770]
            //   68????????           |                     

        $sequence_2 = { f6c103 8b049588de4400 7506 83fa01 7e01 40 8d51ff }
            // n = 7, score = 200
            //   f6c103               | test                cl, 3
            //   8b049588de4400       | mov                 eax, dword ptr [edx*4 + 0x44de88]
            //   7506                 | jne                 8
            //   83fa01               | cmp                 edx, 1
            //   7e01                 | jle                 3
            //   40                   | inc                 eax
            //   8d51ff               | lea                 edx, [ecx - 1]

        $sequence_3 = { 8d9664020000 8d4f64 52 e8???????? 81c670020000 8d4f68 }
            // n = 6, score = 200
            //   8d9664020000         | lea                 edx, [esi + 0x264]
            //   8d4f64               | lea                 ecx, [edi + 0x64]
            //   52                   | push                edx
            //   e8????????           |                     
            //   81c670020000         | add                 esi, 0x270
            //   8d4f68               | lea                 ecx, [edi + 0x68]

        $sequence_4 = { 59 660fb60f 0fb6c1 47 894d0c f680c11c450004 742d }
            // n = 7, score = 200
            //   59                   | pop                 ecx
            //   660fb60f             | movzx               cx, byte ptr [edi]
            //   0fb6c1               | movzx               eax, cl
            //   47                   | inc                 edi
            //   894d0c               | mov                 dword ptr [ebp + 0xc], ecx
            //   f680c11c450004       | test                byte ptr [eax + 0x451cc1], 4
            //   742d                 | je                  0x2f

        $sequence_5 = { c684249d0000006e 889c249e000000 c684249f00000074 c68424a000000053 889c24a1000000 }
            // n = 5, score = 200
            //   c684249d0000006e     | mov                 byte ptr [esp + 0x9d], 0x6e
            //   889c249e000000       | mov                 byte ptr [esp + 0x9e], bl
            //   c684249f00000074     | mov                 byte ptr [esp + 0x9f], 0x74
            //   c68424a000000053     | mov                 byte ptr [esp + 0xa0], 0x53
            //   889c24a1000000       | mov                 byte ptr [esp + 0xa1], bl

        $sequence_6 = { e8???????? c7462844d04300 833d????????00 7416 8b4620 a900008000 740c }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c7462844d04300       | mov                 dword ptr [esi + 0x28], 0x43d044
            //   833d????????00       |                     
            //   7416                 | je                  0x18
            //   8b4620               | mov                 eax, dword ptr [esi + 0x20]
            //   a900008000           | test                eax, 0x800000
            //   740c                 | je                  0xe

        $sequence_7 = { 8a08 0fb6d1 f682c11c450004 7418 3a0e 7508 8a4801 }
            // n = 7, score = 200
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   0fb6d1               | movzx               edx, cl
            //   f682c11c450004       | test                byte ptr [edx + 0x451cc1], 4
            //   7418                 | je                  0x1a
            //   3a0e                 | cmp                 cl, byte ptr [esi]
            //   7508                 | jne                 0xa
            //   8a4801               | mov                 cl, byte ptr [eax + 1]

        $sequence_8 = { 52 8d842470070000 68???????? 50 e8???????? 83c40c e8???????? }
            // n = 7, score = 200
            //   52                   | push                edx
            //   8d842470070000       | lea                 eax, [esp + 0x770]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     

        $sequence_9 = { c20400 8b4714 6a00 8986ac000000 8b4f10 }
            // n = 5, score = 200
            //   c20400               | ret                 4
            //   8b4714               | mov                 eax, dword ptr [edi + 0x14]
            //   6a00                 | push                0
            //   8986ac000000         | mov                 dword ptr [esi + 0xac], eax
            //   8b4f10               | mov                 ecx, dword ptr [edi + 0x10]

    condition:
        7 of them and filesize < 5505024
}