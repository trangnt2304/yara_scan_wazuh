rule win_svcready_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.svcready."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.svcready"
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
        $sequence_0 = { e8???????? 8b542414 8bce 8844241c 8b4508 89442428 }
            // n = 6, score = 500
            //   e8????????           |                     
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   8bce                 | mov                 ecx, esi
            //   8844241c             | mov                 byte ptr [esp + 0x1c], al
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   89442428             | mov                 dword ptr [esp + 0x28], eax

        $sequence_1 = { 8b7918 740b 8b45e8 85d2 75b0 8b09 }
            // n = 6, score = 500
            //   8b7918               | mov                 edi, dword ptr [ecx + 0x18]
            //   740b                 | je                  0xd
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   85d2                 | test                edx, edx
            //   75b0                 | jne                 0xffffffb2
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_2 = { 8b463c 3d00040000 7f3b 8d3c30 68f8000000 57 ff15???????? }
            // n = 7, score = 500
            //   8b463c               | mov                 eax, dword ptr [esi + 0x3c]
            //   3d00040000           | cmp                 eax, 0x400
            //   7f3b                 | jg                  0x3d
            //   8d3c30               | lea                 edi, [eax + esi]
            //   68f8000000           | push                0xf8
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_3 = { 8bc2 c1e81f 03c2 8b542444 03f0 }
            // n = 5, score = 500
            //   8bc2                 | mov                 eax, edx
            //   c1e81f               | shr                 eax, 0x1f
            //   03c2                 | add                 eax, edx
            //   8b542444             | mov                 edx, dword ptr [esp + 0x44]
            //   03f0                 | add                 esi, eax

        $sequence_4 = { 89742410 33c7 2305???????? 0bf3 23f1 8b4c2414 0bcb }
            // n = 7, score = 500
            //   89742410             | mov                 dword ptr [esp + 0x10], esi
            //   33c7                 | xor                 eax, edi
            //   2305????????         |                     
            //   0bf3                 | or                  esi, ebx
            //   23f1                 | and                 esi, ecx
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   0bcb                 | or                  ecx, ebx

        $sequence_5 = { c1cd07 8bc7 d1cb c1e003 33da }
            // n = 5, score = 500
            //   c1cd07               | ror                 ebp, 7
            //   8bc7                 | mov                 eax, edi
            //   d1cb                 | ror                 ebx, 1
            //   c1e003               | shl                 eax, 3
            //   33da                 | xor                 ebx, edx

        $sequence_6 = { 5e 0f95c0 c3 8b5108 8b410c 3bd0 }
            // n = 6, score = 500
            //   5e                   | pop                 esi
            //   0f95c0               | setne               al
            //   c3                   | ret                 
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]
            //   8b410c               | mov                 eax, dword ptr [ecx + 0xc]
            //   3bd0                 | cmp                 edx, eax

        $sequence_7 = { 6a28 e8???????? 8bf8 59 85ff 7502 5f }
            // n = 7, score = 500
            //   6a28                 | push                0x28
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx
            //   85ff                 | test                edi, edi
            //   7502                 | jne                 4
            //   5f                   | pop                 edi

        $sequence_8 = { a3???????? 334c2414 890d???????? 8b0d???????? 33cb 8bf1 894c2414 }
            // n = 7, score = 500
            //   a3????????           |                     
            //   334c2414             | xor                 ecx, dword ptr [esp + 0x14]
            //   890d????????         |                     
            //   8b0d????????         |                     
            //   33cb                 | xor                 ecx, ebx
            //   8bf1                 | mov                 esi, ecx
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx

        $sequence_9 = { 895e28 6a07 5b 395e38 0f4cc3 894638 8b4628 }
            // n = 7, score = 500
            //   895e28               | mov                 dword ptr [esi + 0x28], ebx
            //   6a07                 | push                7
            //   5b                   | pop                 ebx
            //   395e38               | cmp                 dword ptr [esi + 0x38], ebx
            //   0f4cc3               | cmovl               eax, ebx
            //   894638               | mov                 dword ptr [esi + 0x38], eax
            //   8b4628               | mov                 eax, dword ptr [esi + 0x28]

    condition:
        7 of them and filesize < 1187840
}