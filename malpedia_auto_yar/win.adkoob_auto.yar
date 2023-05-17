rule win_adkoob_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.adkoob."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adkoob"
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
        $sequence_0 = { 8bd0 8bcf e8???????? 894628 33c0 8b5324 59 }
            // n = 7, score = 400
            //   8bd0                 | mov                 edx, eax
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   894628               | mov                 dword ptr [esi + 0x28], eax
            //   33c0                 | xor                 eax, eax
            //   8b5324               | mov                 edx, dword ptr [ebx + 0x24]
            //   59                   | pop                 ecx

        $sequence_1 = { e8???????? 8b4d08 5f 5e 8b510c 8b4a10 89410c }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8b510c               | mov                 edx, dword ptr [ecx + 0xc]
            //   8b4a10               | mov                 ecx, dword ptr [edx + 0x10]
            //   89410c               | mov                 dword ptr [ecx + 0xc], eax

        $sequence_2 = { 89040e 8b4750 8b4b08 89443104 83c60c 8b45fc 40 }
            // n = 7, score = 400
            //   89040e               | mov                 dword ptr [esi + ecx], eax
            //   8b4750               | mov                 eax, dword ptr [edi + 0x50]
            //   8b4b08               | mov                 ecx, dword ptr [ebx + 8]
            //   89443104             | mov                 dword ptr [ecx + esi + 4], eax
            //   83c60c               | add                 esi, 0xc
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   40                   | inc                 eax

        $sequence_3 = { e8???????? 8bcb e8???????? 8b5df8 85db 744b 6a00 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   85db                 | test                ebx, ebx
            //   744b                 | je                  0x4d
            //   6a00                 | push                0

        $sequence_4 = { ff700c 6a57 5a e8???????? 8b4510 83c40c 8bcb }
            // n = 7, score = 400
            //   ff700c               | push                dword ptr [eax + 0xc]
            //   6a57                 | push                0x57
            //   5a                   | pop                 edx
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c40c               | add                 esp, 0xc
            //   8bcb                 | mov                 ecx, ebx

        $sequence_5 = { 8d8c2480000000 e8???????? 88442413 84c0 0f847e010000 8b542434 8b4c2418 }
            // n = 7, score = 400
            //   8d8c2480000000       | lea                 ecx, [esp + 0x80]
            //   e8????????           |                     
            //   88442413             | mov                 byte ptr [esp + 0x13], al
            //   84c0                 | test                al, al
            //   0f847e010000         | je                  0x184
            //   8b542434             | mov                 edx, dword ptr [esp + 0x34]
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]

        $sequence_6 = { 89435c e8???????? 8b03 83c414 397810 0f840effffff 33c0 }
            // n = 7, score = 400
            //   89435c               | mov                 dword ptr [ebx + 0x5c], eax
            //   e8????????           |                     
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   83c414               | add                 esp, 0x14
            //   397810               | cmp                 dword ptr [eax + 0x10], edi
            //   0f840effffff         | je                  0xffffff14
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 8bc8 6a00 e8???????? 59 85c0 0f857a110000 8b85c8feffff }
            // n = 7, score = 400
            //   8bc8                 | mov                 ecx, eax
            //   6a00                 | push                0
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   0f857a110000         | jne                 0x1180
            //   8b85c8feffff         | mov                 eax, dword ptr [ebp - 0x138]

        $sequence_8 = { e8???????? 8d8d14feffff e8???????? 32c0 e8???????? c3 6a04 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8d8d14feffff         | lea                 ecx, [ebp - 0x1ec]
            //   e8????????           |                     
            //   32c0                 | xor                 al, al
            //   e8????????           |                     
            //   c3                   | ret                 
            //   6a04                 | push                4

        $sequence_9 = { 8d8d8cfdffff c645fc09 e8???????? 8d5e10 8d9574ffffff 899d88fdffff 8d8d70feffff }
            // n = 7, score = 400
            //   8d8d8cfdffff         | lea                 ecx, [ebp - 0x274]
            //   c645fc09             | mov                 byte ptr [ebp - 4], 9
            //   e8????????           |                     
            //   8d5e10               | lea                 ebx, [esi + 0x10]
            //   8d9574ffffff         | lea                 edx, [ebp - 0x8c]
            //   899d88fdffff         | mov                 dword ptr [ebp - 0x278], ebx
            //   8d8d70feffff         | lea                 ecx, [ebp - 0x190]

    condition:
        7 of them and filesize < 1867776
}