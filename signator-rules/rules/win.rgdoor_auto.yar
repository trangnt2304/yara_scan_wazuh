rule win_rgdoor_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.rgdoor."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rgdoor"
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
        $sequence_0 = { 488b01 48635004 488d0583780200 4889040a }
            // n = 4, score = 100
            //   488b01               | cmp                 eax, 3
            //   48635004             | jge                 0x706
            //   488d0583780200       | jae                 0x700
            //   4889040a             | dec                 eax

        $sequence_1 = { e8???????? e8???????? 8918 e9???????? }
            // n = 4, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   8918                 | dec                 esp
            //   e9????????           |                     

        $sequence_2 = { 418bdc 48ffc7 41381c3f 75f7 488b4c2440 }
            // n = 5, score = 100
            //   418bdc               | inc                 ecx
            //   48ffc7               | mov                 dword ptr [eax], 0xffffffff
            //   41381c3f             | xor                 eax, eax
            //   75f7                 | dec                 eax
            //   488b4c2440           | add                 esp, 0x120

        $sequence_3 = { 7453 663931 744e 488d1588da0000 e8???????? 85c0 743e }
            // n = 7, score = 100
            //   7453                 | dec                 eax
            //   663931               | mov                 ecx, esi
            //   744e                 | dec                 eax
            //   488d1588da0000       | add                 ebx, eax
            //   e8????????           |                     
            //   85c0                 | jmp                 0x5a1
            //   743e                 | dec                 ebx

        $sequence_4 = { 48c1fb05 e8???????? 83e01f 486bc858 48030cde eb07 488d0d2bdf0100 }
            // n = 7, score = 100
            //   48c1fb05             | dec                 eax
            //   e8????????           |                     
            //   83e01f               | lea                 ecx, [ebp - 0x30]
            //   486bc858             | dec                 eax
            //   48030cde             | mov                 dword ptr [ebp - 0x30], eax
            //   eb07                 | movaps              xmm6, xmmword ptr [esp + 0x3a0]
            //   488d0d2bdf0100       | dec                 eax

        $sequence_5 = { 488bd6 498bcc e8???????? 488bd8 488bd0 488d4df0 }
            // n = 6, score = 100
            //   488bd6               | je                  0x1f6d
            //   498bcc               | mov                 ecx, 9
            //   e8????????           |                     
            //   488bd8               | nop                 
            //   488bd0               | mov                 dword ptr [esp + 0x74], edi
            //   488d4df0             | jmp                 0x1f90

        $sequence_6 = { 7429 488d15d4ed0100 498bce e8???????? 8b0d???????? 85c0 41be01000000 }
            // n = 7, score = 100
            //   7429                 | lea                 edx, [ecx - 0x7e]
            //   488d15d4ed0100       | xor                 ecx, ecx
            //   498bce               | inc                 esi
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   85c0                 | mov                 byte ptr [eax + esi + 9], cl
            //   41be01000000         | test                dl, dl

        $sequence_7 = { e8???????? 488bcf 488d356b040200 4863d8 48c1fb05 e8???????? 83e01f }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bcf               | mov                 eax, esp
            //   488d356b040200       | dec                 eax
            //   4863d8               | mov                 ecx, ebx
            //   48c1fb05             | dec                 eax
            //   e8????????           |                     
            //   83e01f               | test                eax, eax

        $sequence_8 = { 4b8b8cea503f0300 4288443109 8a45d9 4b8b8cea503f0300 4288443139 }
            // n = 5, score = 100
            //   4b8b8cea503f0300     | mov                 dword ptr [ecx + ecx - 0x10], eax
            //   4288443109           | dec                 ecx
            //   8a45d9               | mov                 eax, dword ptr [ecx - 0x10]
            //   4b8b8cea503f0300     | dec                 eax
            //   4288443139           | arpl                word ptr [eax + 4], cx

        $sequence_9 = { 488d05dfc00200 4889442438 0f28442430 660f7f442430 }
            // n = 4, score = 100
            //   488d05dfc00200       | mov                 dword ptr [esp + 0x10], ebx
            //   4889442438           | dec                 eax
            //   0f28442430           | mov                 dword ptr [esp + 0x18], ebp
            //   660f7f442430         | dec                 eax

    condition:
        7 of them and filesize < 475136
}