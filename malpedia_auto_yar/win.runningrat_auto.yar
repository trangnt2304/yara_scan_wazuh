rule win_runningrat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.runningrat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.runningrat"
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
        $sequence_0 = { 56 ff15???????? 56 ff15???????? 8b8c2418010000 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b8c2418010000       | mov                 ecx, dword ptr [esp + 0x118]

        $sequence_1 = { 68???????? 68???????? 64a100000000 50 64892500000000 81ec9c020000 53 }
            // n = 7, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   64a100000000         | mov                 eax, dword ptr fs:[0]
            //   50                   | push                eax
            //   64892500000000       | mov                 dword ptr fs:[0], esp
            //   81ec9c020000         | sub                 esp, 0x29c
            //   53                   | push                ebx

        $sequence_2 = { 884c2414 6a06 50 8bce 885c2424 88442420 e8???????? }
            // n = 7, score = 200
            //   884c2414             | mov                 byte ptr [esp + 0x14], cl
            //   6a06                 | push                6
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   885c2424             | mov                 byte ptr [esp + 0x24], bl
            //   88442420             | mov                 byte ptr [esp + 0x20], al
            //   e8????????           |                     

        $sequence_3 = { 5f 751d c7837801000000000000 c7837c01000000000000 5e }
            // n = 5, score = 200
            //   5f                   | pop                 edi
            //   751d                 | jne                 0x1f
            //   c7837801000000000000     | mov    dword ptr [ebx + 0x178], 0
            //   c7837c01000000000000     | mov    dword ptr [ebx + 0x17c], 0
            //   5e                   | pop                 esi

        $sequence_4 = { 897318 8b7b10 8bce 8b742420 8bc1 c1e902 f3a5 }
            // n = 7, score = 200
            //   897318               | mov                 dword ptr [ebx + 0x18], esi
            //   8b7b10               | mov                 edi, dword ptr [ebx + 0x10]
            //   8bce                 | mov                 ecx, esi
            //   8b742420             | mov                 esi, dword ptr [esp + 0x20]
            //   8bc1                 | mov                 eax, ecx
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_5 = { 51 6a64 52 68???????? 68???????? }
            // n = 5, score = 200
            //   51                   | push                ecx
            //   6a64                 | push                0x64
            //   52                   | push                edx
            //   68????????           |                     
            //   68????????           |                     

        $sequence_6 = { ffd6 eb5b 8b4c2414 8b542418 8d442413 894d70 }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   eb5b                 | jmp                 0x5d
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   8d442413             | lea                 eax, [esp + 0x13]
            //   894d70               | mov                 dword ptr [ebp + 0x70], ecx

        $sequence_7 = { 8d88740a0000 8988280b0000 33c9 c780180b000080cd0110 }
            // n = 4, score = 200
            //   8d88740a0000         | lea                 ecx, [eax + 0xa74]
            //   8988280b0000         | mov                 dword ptr [eax + 0xb28], ecx
            //   33c9                 | xor                 ecx, ecx
            //   c780180b000080cd0110     | mov    dword ptr [eax + 0xb18], 0x1001cd80

        $sequence_8 = { 83eb02 eb34 8b74243c 8b762c }
            // n = 4, score = 100
            //   83eb02               | sub                 ebx, 2
            //   eb34                 | jmp                 0x36
            //   8b74243c             | mov                 esi, dword ptr [esp + 0x3c]
            //   8b762c               | mov                 esi, dword ptr [esi + 0x2c]

        $sequence_9 = { c68424350500006c c68424360500006f c684243705000063 c684243805000000 e8???????? }
            // n = 5, score = 100
            //   c68424350500006c     | mov                 byte ptr [esp + 0x535], 0x6c
            //   c68424360500006f     | mov                 byte ptr [esp + 0x536], 0x6f
            //   c684243705000063     | mov                 byte ptr [esp + 0x537], 0x63
            //   c684243805000000     | mov                 byte ptr [esp + 0x538], 0
            //   e8????????           |                     

        $sequence_10 = { 47 3bbc2410010000 72ca 8b542414 8b8c148c000000 8b94242c010000 8bdd }
            // n = 7, score = 100
            //   47                   | inc                 edi
            //   3bbc2410010000       | cmp                 edi, dword ptr [esp + 0x110]
            //   72ca                 | jb                  0xffffffcc
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   8b8c148c000000       | mov                 ecx, dword ptr [esp + edx + 0x8c]
            //   8b94242c010000       | mov                 edx, dword ptr [esp + 0x12c]
            //   8bdd                 | mov                 ebx, ebp

        $sequence_11 = { 68f5000000 8d44244f 6a00 50 }
            // n = 4, score = 100
            //   68f5000000           | push                0xf5
            //   8d44244f             | lea                 eax, [esp + 0x4f]
            //   6a00                 | push                0
            //   50                   | push                eax

        $sequence_12 = { 8b461c 896c2418 3bf9 7309 2bcf 49 894c2414 }
            // n = 7, score = 100
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   896c2418             | mov                 dword ptr [esp + 0x18], ebp
            //   3bf9                 | cmp                 edi, ecx
            //   7309                 | jae                 0xb
            //   2bcf                 | sub                 ecx, edi
            //   49                   | dec                 ecx
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx

        $sequence_13 = { 8d8c246c010000 51 ff15???????? 8d742460 e8???????? }
            // n = 5, score = 100
            //   8d8c246c010000       | lea                 ecx, [esp + 0x16c]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d742460             | lea                 esi, [esp + 0x60]
            //   e8????????           |                     

        $sequence_14 = { c74718f0692a00 6afd e9???????? 8b542414 895620 8b542444 }
            // n = 6, score = 100
            //   c74718f0692a00       | mov                 dword ptr [edi + 0x18], 0x2a69f0
            //   6afd                 | push                -3
            //   e9????????           |                     
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   895620               | mov                 dword ptr [esi + 0x20], edx
            //   8b542444             | mov                 edx, dword ptr [esp + 0x44]

    condition:
        7 of them and filesize < 278528
}