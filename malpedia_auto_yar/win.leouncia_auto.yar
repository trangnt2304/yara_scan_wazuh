rule win_leouncia_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.leouncia."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.leouncia"
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
        $sequence_0 = { 83c404 c1e018 0bc8 5f 5e }
            // n = 5, score = 100
            //   83c404               | add                 esp, 4
            //   c1e018               | shl                 eax, 0x18
            //   0bc8                 | or                  ecx, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_1 = { 8bbc2464040000 33ed 8d542410 895c2410 52 }
            // n = 5, score = 100
            //   8bbc2464040000       | mov                 edi, dword ptr [esp + 0x464]
            //   33ed                 | xor                 ebp, ebp
            //   8d542410             | lea                 edx, [esp + 0x10]
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx
            //   52                   | push                edx

        $sequence_2 = { 0f8f97000000 56 57 8b7d0c 8b34bd24a74000 }
            // n = 5, score = 100
            //   0f8f97000000         | jg                  0x9d
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8b34bd24a74000       | mov                 esi, dword ptr [edi*4 + 0x40a724]

        $sequence_3 = { 8b7d08 8d05d4ae4000 83780800 753b b0ff 8bff }
            // n = 6, score = 100
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d05d4ae4000         | lea                 eax, [0x40aed4]
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   753b                 | jne                 0x3d
            //   b0ff                 | mov                 al, 0xff
            //   8bff                 | mov                 edi, edi

        $sequence_4 = { 56 53 8b750c 8b7d08 8d05d4ae4000 83780800 753b }
            // n = 7, score = 100
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d05d4ae4000         | lea                 eax, [0x40aed4]
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   753b                 | jne                 0x3d

        $sequence_5 = { 6a64 8bdf 2bde ff15???????? 3bfe }
            // n = 5, score = 100
            //   6a64                 | push                0x64
            //   8bdf                 | mov                 ebx, edi
            //   2bde                 | sub                 ebx, esi
            //   ff15????????         |                     
            //   3bfe                 | cmp                 edi, esi

        $sequence_6 = { 50 52 e8???????? 8b442420 83e810 89442420 c644046000 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   83e810               | sub                 eax, 0x10
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   c644046000           | mov                 byte ptr [esp + eax + 0x60], 0

        $sequence_7 = { e8???????? 85c0 75d9 5b 85f6 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   75d9                 | jne                 0xffffffdb
            //   5b                   | pop                 ebx
            //   85f6                 | test                esi, esi

        $sequence_8 = { b949000000 8dbc2414010000 c784241001000000000000 50 6a02 f3ab }
            // n = 6, score = 100
            //   b949000000           | mov                 ecx, 0x49
            //   8dbc2414010000       | lea                 edi, [esp + 0x114]
            //   c784241001000000000000     | mov    dword ptr [esp + 0x110], 0
            //   50                   | push                eax
            //   6a02                 | push                2
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_9 = { 8db42430040000 8b0e 83c208 8908 8b4e04 894804 8a0d???????? }
            // n = 7, score = 100
            //   8db42430040000       | lea                 esi, [esp + 0x430]
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   83c208               | add                 edx, 8
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8a0d????????         |                     

    condition:
        7 of them and filesize < 114688
}