rule win_polyvice_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.polyvice."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyvice"
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
        $sequence_0 = { 41c1cf07 4589fe 4589d7 41c1c20e 4531f2 41c1ef03 4531fa }
            // n = 7, score = 100
            //   41c1cf07             | lea                 ecx, [esi + eax]
            //   4589fe               | inc                 esp
            //   4589d7               | movzx               edx, word ptr [ebp - 0x12]
            //   41c1c20e             | jmp                 0xc4f
            //   4531f2               | inc                 sp
            //   41c1ef03             | cmp                 esi, edx
            //   4531fa               | ja                  0xd62

        $sequence_1 = { 4889da c6470407 66894702 e8???????? 488d8ed8070000 0fb7c0 4801c3 }
            // n = 7, score = 100
            //   4889da               | add                 eax, esp
            //   c6470407             | inc                 edi
            //   66894702             | lea                 esi, [ebp]
            //   e8????????           |                     
            //   488d8ed8070000       | inc                 ebp
            //   0fb7c0               | mov                 ebp, edx
            //   4801c3               | inc                 edx

        $sequence_2 = { 488b5028 4889942490000000 488b5030 4889942498000000 488b5038 488b4040 48899424a0000000 }
            // n = 7, score = 100
            //   488b5028             | add                 edx, 1
            //   4889942490000000     | dec                 eax
            //   488b5030             | add                 eax, 0x48
            //   4889942498000000     | dec                 eax
            //   488b5038             | cmp                 edx, 0x12
            //   488b4040             | je                  0x1c81
            //   48899424a0000000     | inc                 ebp

        $sequence_3 = { 488d6c2430 4889f1 895c2420 4d89f1 448b8424e8000000 48896c2428 488b9424e0000000 }
            // n = 7, score = 100
            //   488d6c2430           | dec                 ecx
            //   4889f1               | mov                 dword ptr [esi + 8], eax
            //   895c2420             | dec                 eax
            //   4d89f1               | mov                 ecx, edi
            //   448b8424e8000000     | dec                 ecx
            //   48896c2428           | mov                 edx, dword ptr [esi + 8]
            //   488b9424e0000000     | dec                 eax

        $sequence_4 = { 4131c5 410fb6400a c1e008 4131c5 410fb6400c }
            // n = 5, score = 100
            //   4131c5               | dec                 ebp
            //   410fb6400a           | add                 eax, eax
            //   c1e008               | dec                 ebp
            //   4131c5               | arpl                ax, ax
            //   410fb6400c           | dec                 eax

        $sequence_5 = { 488b4040 4889942428030000 4889842430030000 488b05???????? 488b10 4889942438030000 488b5008 }
            // n = 7, score = 100
            //   488b4040             | test                al, al
            //   4889942428030000     | je                  0x1074
            //   4889842430030000     | dec                 eax
            //   488b05????????       |                     
            //   488b10               | arpl                word ptr [esp + 0x30], ax
            //   4889942438030000     | xor                 edx, edx
            //   488b5008             | dec                 eax

        $sequence_6 = { 894608 49c1e820 4c01ca 4c01c2 4101fb 44891e 89560c }
            // n = 7, score = 100
            //   894608               | dec                 esp
            //   49c1e820             | lea                 eax, [edi + 0x7d8]
            //   4c01ca               | mov                 edx, esi
            //   4c01c2               | movzx               eax, ax
            //   4101fb               | dec                 eax
            //   44891e               | add                 ebx, eax
            //   89560c               | dec                 eax

        $sequence_7 = { 4401d0 31dd 336c2408 4189ea 8b6c2430 41d1c2 4489d3 }
            // n = 7, score = 100
            //   4401d0               | add                 ebx, edx
            //   31dd                 | mov                 edx, eax
            //   336c2408             | inc                 ecx
            //   4189ea               | ror                 eax, 0xb
            //   8b6c2430             | inc                 esp
            //   41d1c2               | xor                 edx, ebx
            //   4489d3               | inc                 esp

        $sequence_8 = { 55 57 56 53 4883ec58 488d6c2420 4889cb }
            // n = 7, score = 100
            //   55                   | and                 ecx, 0xff00
            //   57                   | inc                 esp
            //   56                   | or                  ecx, eax
            //   53                   | dec                 eax
            //   4883ec58             | lea                 edx, [ebx + edx*4]
            //   488d6c2420           | nop                 
            //   4889cb               | inc                 esp

        $sequence_9 = { 01c2 4489e0 c1c806 31c1 4489e0 c1c007 31c1 }
            // n = 7, score = 100
            //   01c2                 | inc                 ebp
            //   4489e0               | xor                 esi, edx
            //   c1c806               | inc                 ecx
            //   31c1                 | add                 esp, eax
            //   4489e0               | inc                 ebp
            //   c1c007               | mov                 ecx, esi
            //   31c1                 | inc                 esp

    condition:
        7 of them and filesize < 369664
}