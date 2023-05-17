rule win_cloudburst_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.cloudburst."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cloudburst"
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
        $sequence_0 = { b807000000 4885c9 440f44e0 4963c7 33ff 4533f6 4889442440 }
            // n = 7, score = 100
            //   b807000000           | inc                 esp
            //   4885c9               | mov                 dword ptr [esp + 0x40], esi
            //   440f44e0             | dec                 eax
            //   4963c7               | mov                 dword ptr [ebp + 0xb8], 0xf
            //   33ff                 | dec                 esp
            //   4533f6               | mov                 dword ptr [ebp + 0xb0], esi
            //   4889442440           | inc                 esp

        $sequence_1 = { e8???????? 488b6c2438 488b742440 488b7c2448 488903 488b5c2430 4883c420 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b6c2438           | mov                 edx, esi
            //   488b742440           | dec                 eax
            //   488b7c2448           | lea                 edi, [ebp + 0x180]
            //   488903               | inc                 ebp
            //   488b5c2430           | mov                 ecx, ecx
            //   4883c420             | dec                 eax

        $sequence_2 = { c3 c7024b000000 488b5c2430 4883c420 5f c3 8079017c }
            // n = 7, score = 100
            //   c3                   | xor                 eax, dword ptr [esi + eax*4 + 0xd5960]
            //   c7024b000000         | inc                 ecx
            //   488b5c2430           | mov                 eax, ebx
            //   4883c420             | inc                 ebp
            //   5f                   | xor                 eax, dword ptr [ebp + 0xc]
            //   c3                   | shr                 eax, 8
            //   8079017c             | movzx               edx, al

        $sequence_3 = { ba10010000 488bcf 41ff5370 b801000000 488b5c2430 4883c420 5f }
            // n = 7, score = 100
            //   ba10010000           | jne                 0x2cd
            //   488bcf               | inc                 esp
            //   41ff5370             | mov                 eax, eax
            //   b801000000           | cmp                 byte ptr [edx], 0
            //   488b5c2430           | je                  0x2be
            //   4883c420             | dec                 eax
            //   5f                   | inc                 eax

        $sequence_4 = { 85c0 0f8522020000 40386b14 7713 488d542430 488bcb e8???????? }
            // n = 7, score = 100
            //   85c0                 | mov                 eax, dword ptr [ecx]
            //   0f8522020000         | dec                 eax
            //   40386b14             | test                eax, eax
            //   7713                 | inc                 ecx
            //   488d542430           | cmp                 ecx, 1
            //   488bcb               | jbe                 0x83d
            //   e8????????           |                     

        $sequence_5 = { ba1e080000 ff15???????? 8bde 4532e4 4532f6 381d???????? 0f85c8020000 }
            // n = 7, score = 100
            //   ba1e080000           | mov                 eax, edx
            //   ff15????????         |                     
            //   8bde                 | inc                 eax
            //   4532e4               | dec                 eax
            //   4532f6               | add                 ecx, 0x18
            //   381d????????         |                     
            //   0f85c8020000         | cmp                 eax, 0xa

        $sequence_6 = { 83fa01 448bea 0f94c0 4533ff 488be9 41884628 488b7908 }
            // n = 7, score = 100
            //   83fa01               | dec                 esp
            //   448bea               | lea                 eax, [eax + 0x20]
            //   0f94c0               | xor                 ebx, ebx
            //   4533ff               | inc                 ebp
            //   488be9               | mov                 edi, ecx
            //   41884628             | inc                 ecx
            //   488b7908             | push                edi

        $sequence_7 = { 884a08 488b45b8 448b4dc4 440fb7400a 41ffc0 eb09 3cf2 }
            // n = 7, score = 100
            //   884a08               | mov                 ebp, ebp
            //   488b45b8             | dec                 esp
            //   448b4dc4             | mov                 dword ptr [eax - 0x58], ebp
            //   440fb7400a           | dec                 esp
            //   41ffc0               | mov                 dword ptr [eax + 0x20], ebp
            //   eb09                 | dec                 esp
            //   3cf2                 | mov                 dword ptr [eax + 0x18], ebp

        $sequence_8 = { 4d85c9 7418 8b02 413901 7411 488d15e8540700 e8???????? }
            // n = 7, score = 100
            //   4d85c9               | dec                 eax
            //   7418                 | mov                 dword ptr [edx + 8], eax
            //   8b02                 | dec                 eax
            //   413901               | mov                 dword ptr [edx + 0x10], eax
            //   7411                 | call                dword ptr [eax + 0x28]
            //   488d15e8540700       | inc                 esp
            //   e8????????           |                     

        $sequence_9 = { e9???????? 4883c9ff 33c0 488dbd00070000 f2ae 488d9500070000 48f7d1 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   4883c9ff             | dec                 eax
            //   33c0                 | mov                 esi, edx
            //   488dbd00070000       | mov                 ecx, 8
            //   f2ae                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]
            //   488d9500070000       | dec                 eax
            //   48f7d1               | add                 esp, 0x20

    condition:
        7 of them and filesize < 2363392
}