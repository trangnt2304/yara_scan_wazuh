rule win_spider_rat_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.spider_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spider_rat"
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
        $sequence_0 = { 488b11 ff5210 8bc6 eb27 4c8d4f10 4c8d4720 }
            // n = 6, score = 200
            //   488b11               | cmp                 dword ptr [esp + 0x30], edi
            //   ff5210               | je                  0x1110
            //   8bc6                 | dec                 esp
            //   eb27                 | lea                 eax, [0xfffe5bc8]
            //   4c8d4f10             | dec                 ebx
            //   4c8d4720             | mov                 eax, dword ptr [eax + esi*8 + 0x77ae0]

        $sequence_1 = { 483bc1 72f0 0fba65180d 7351 eb4c 4533c0 488bd6 }
            // n = 7, score = 200
            //   483bc1               | dec                 eax
            //   72f0                 | add                 ecx, edx
            //   0fba65180d           | jmp                 ecx
            //   7351                 | inc                 esp
            //   eb4c                 | cmp                 dword ptr [edi + 0x10], esi
            //   4533c0               | jne                 0x23cb
            //   488bd6               | mov                 edx, dword ptr [ebx + 0x108]

        $sequence_2 = { 4c8be0 e9???????? 4b8b8cf0e07a0700 4c8d4c2430 488d9424b0000000 488b0c31 41b801000000 }
            // n = 7, score = 200
            //   4c8be0               | dec                 eax
            //   e9????????           |                     
            //   4b8b8cf0e07a0700     | sub                 esp, 0x50
            //   4c8d4c2430           | dec                 eax
            //   488d9424b0000000     | xor                 eax, esp
            //   488b0c31             | dec                 eax
            //   41b801000000         | mov                 dword ptr [esp + 0x48], eax

        $sequence_3 = { 4885db 0f845e040000 4885c0 0f846d040000 ba08000000 e9???????? }
            // n = 6, score = 200
            //   4885db               | cmp                 ecx, 1
            //   0f845e040000         | jne                 0x740
            //   4885c0               | dec                 eax
            //   0f846d040000         | arpl                word ptr [ebx + 8], ax
            //   ba08000000           | dec                 eax
            //   e9????????           |                     

        $sequence_4 = { 4c8d7e08 498bcf 0f1f440000 0fb601 8803 48ffc1 48ffc3 }
            // n = 7, score = 200
            //   4c8d7e08             | dec                 eax
            //   498bcf               | test                edx, edx
            //   0f1f440000           | jne                 0xe0b
            //   0fb601               | xor                 eax, eax
            //   8803                 | dec                 eax
            //   48ffc1               | test                ecx, ecx
            //   48ffc3               | dec                 eax

        $sequence_5 = { 90 488b4c2440 483bcf 7407 488b01 ff5010 90 }
            // n = 7, score = 200
            //   90                   | mov                 edi, dword ptr [esp + 0x48]
            //   488b4c2440           | dec                 eax
            //   483bcf               | add                 esp, 0x20
            //   7407                 | inc                 ecx
            //   488b01               | pop                 esp
            //   ff5010               | ret                 
            //   90                   | dec                 eax

        $sequence_6 = { 48896c2410 4889742418 57 4883ec20 498be9 488bf9 4d85c9 }
            // n = 7, score = 200
            //   48896c2410           | dec                 esp
            //   4889742418           | mov                 ebx, dword ptr [ebp]
            //   57                   | dec                 esp
            //   4883ec20             | mov                 ecx, dword ptr [esp + 0x88]
            //   498be9               | dec                 eax
            //   488bf9               | mov                 dword ptr [esp + 0x30], eax
            //   4d85c9               | dec                 eax

        $sequence_7 = { 4154 4881ec40010000 488b05???????? 4833c4 4889842430010000 33db 418be8 }
            // n = 7, score = 200
            //   4154                 | mov                 eax, 0x18
            //   4881ec40010000       | dec                 eax
            //   488b05????????       |                     
            //   4833c4               | lea                 edx, [0x59e17]
            //   4889842430010000     | dec                 eax
            //   33db                 | lea                 ecx, [esp + 0x78]
            //   418be8               | jne                 0x18aa

        $sequence_8 = { 488b4c2430 48890a 418bc7 eb19 488d15dc5f0400 488944da08 b907000000 }
            // n = 7, score = 200
            //   488b4c2430           | inc                 ebp
            //   48890a               | xor                 ecx, ecx
            //   418bc7               | inc                 ebp
            //   eb19                 | xor                 eax, eax
            //   488d15dc5f0400       | mov                 edx, 0x364
            //   488944da08           | jne                 0x898
            //   b907000000           | inc                 ebp

        $sequence_9 = { 7451 488d1568db0300 488bcb e8???????? 85c0 751e 8b4f24 }
            // n = 7, score = 200
            //   7451                 | dec                 ecx
            //   488d1568db0300       | mov                 edi, ecx
            //   488bcb               | inc                 ecx
            //   e8????????           |                     
            //   85c0                 | mov                 esi, eax
            //   751e                 | dec                 eax
            //   8b4f24               | mov                 ebx, ecx

    condition:
        7 of them and filesize < 1107968
}