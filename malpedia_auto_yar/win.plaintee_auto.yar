rule win_plaintee_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.plaintee."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plaintee"
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
        $sequence_0 = { 8b442414 52 50 6a00 56 51 8b4c241c }
            // n = 7, score = 300
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   52                   | push                edx
            //   50                   | push                eax
            //   6a00                 | push                0
            //   56                   | push                esi
            //   51                   | push                ecx
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]

        $sequence_1 = { 52 56 50 ff15???????? 83f85a 721a }
            // n = 6, score = 300
            //   52                   | push                edx
            //   56                   | push                esi
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83f85a               | cmp                 eax, 0x5a
            //   721a                 | jb                  0x1c

        $sequence_2 = { ff15???????? 85c0 740a b001 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   b001                 | mov                 al, 1

        $sequence_3 = { 33f6 8bce e8???????? 8a8669010000 84c0 }
            // n = 5, score = 300
            //   33f6                 | xor                 esi, esi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8a8669010000         | mov                 al, byte ptr [esi + 0x169]
            //   84c0                 | test                al, al

        $sequence_4 = { 83ec08 68???????? c744240400000000 c744240800000000 ff15???????? 85c0 741a }
            // n = 7, score = 300
            //   83ec08               | sub                 esp, 8
            //   68????????           |                     
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741a                 | je                  0x1c

        $sequence_5 = { 881c08 40 3bc6 7cf3 5b 8b542418 }
            // n = 6, score = 300
            //   881c08               | mov                 byte ptr [eax + ecx], bl
            //   40                   | inc                 eax
            //   3bc6                 | cmp                 eax, esi
            //   7cf3                 | jl                  0xfffffff5
            //   5b                   | pop                 ebx
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]

        $sequence_6 = { 6a02 ff15???????? 83f8ff 898638010000 750a }
            // n = 5, score = 300
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   898638010000         | mov                 dword ptr [esi + 0x138], eax
            //   750a                 | jne                 0xc

        $sequence_7 = { ffd0 8b4c2400 33c0 83f905 0f94c0 }
            // n = 5, score = 300
            //   ffd0                 | call                eax
            //   8b4c2400             | mov                 ecx, dword ptr [esp]
            //   33c0                 | xor                 eax, eax
            //   83f905               | cmp                 ecx, 5
            //   0f94c0               | sete                al

        $sequence_8 = { 8bcb 66a5 8bc1 8bf5 }
            // n = 4, score = 300
            //   8bcb                 | mov                 ecx, ebx
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   8bc1                 | mov                 eax, ecx
            //   8bf5                 | mov                 esi, ebp

        $sequence_9 = { ff15???????? 83c438 68???????? ff15???????? 8b400c }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   83c438               | add                 esp, 0x38
            //   68????????           |                     
            //   ff15????????         |                     
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]

    condition:
        7 of them and filesize < 73728
}