rule win_r980_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.r980."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.r980"
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
        $sequence_0 = { 0f95c0 84c0 7411 c645fc13 ff772c ff7728 6a01 }
            // n = 7, score = 200
            //   0f95c0               | setne               al
            //   84c0                 | test                al, al
            //   7411                 | je                  0x13
            //   c645fc13             | mov                 byte ptr [ebp - 4], 0x13
            //   ff772c               | push                dword ptr [edi + 0x2c]
            //   ff7728               | push                dword ptr [edi + 0x28]
            //   6a01                 | push                1

        $sequence_1 = { 720d 40 8d4dd8 50 ff75d8 e8???????? 8d45d8 }
            // n = 7, score = 200
            //   720d                 | jb                  0xf
            //   40                   | inc                 eax
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   50                   | push                eax
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   e8????????           |                     
            //   8d45d8               | lea                 eax, [ebp - 0x28]

        $sequence_2 = { b89c010000 c645fc1c 68???????? b9???????? 66a3???????? e8???????? b89d010000 }
            // n = 7, score = 200
            //   b89c010000           | mov                 eax, 0x19c
            //   c645fc1c             | mov                 byte ptr [ebp - 4], 0x1c
            //   68????????           |                     
            //   b9????????           |                     
            //   66a3????????         |                     
            //   e8????????           |                     
            //   b89d010000           | mov                 eax, 0x19d

        $sequence_3 = { 85ff 7444 660f1f840000000000 8b0b ba02000000 8d4108 8710 }
            // n = 7, score = 200
            //   85ff                 | test                edi, edi
            //   7444                 | je                  0x46
            //   660f1f840000000000     | nop    word ptr [eax + eax]
            //   8b0b                 | mov                 ecx, dword ptr [ebx]
            //   ba02000000           | mov                 edx, 2
            //   8d4108               | lea                 eax, [ecx + 8]
            //   8710                 | xchg                dword ptr [eax], edx

        $sequence_4 = { 8b45e4 8b0c85f0285200 8b45e8 f644012880 7446 0fbec3 83e800 }
            // n = 7, score = 200
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b0c85f0285200       | mov                 ecx, dword ptr [eax*4 + 0x5228f0]
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   f644012880           | test                byte ptr [ecx + eax + 0x28], 0x80
            //   7446                 | je                  0x48
            //   0fbec3               | movsx               eax, bl
            //   83e800               | sub                 eax, 0

        $sequence_5 = { 8bd9 895dec 8b4508 8d5328 8b7510 8d4a10 c681f900000000 }
            // n = 7, score = 200
            //   8bd9                 | mov                 ebx, ecx
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d5328               | lea                 edx, [ebx + 0x28]
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]
            //   8d4a10               | lea                 ecx, [edx + 0x10]
            //   c681f900000000       | mov                 byte ptr [ecx + 0xf9], 0

        $sequence_6 = { 7462 85f6 741f 56 c745fc00000000 e8???????? 6a14 }
            // n = 7, score = 200
            //   7462                 | je                  0x64
            //   85f6                 | test                esi, esi
            //   741f                 | je                  0x21
            //   56                   | push                esi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     
            //   6a14                 | push                0x14

        $sequence_7 = { 50 8d45f4 64a300000000 8bf2 51 8d4de4 e8???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf2                 | mov                 esi, edx
            //   51                   | push                ecx
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     

        $sequence_8 = { ff75d8 8d4dd8 e8???????? 8bc6 eb02 33c0 8b4df4 }
            // n = 7, score = 200
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_9 = { 83780400 7456 83ec08 8bc4 53 50 e8???????? }
            // n = 7, score = 200
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   7456                 | je                  0x58
            //   83ec08               | sub                 esp, 8
            //   8bc4                 | mov                 eax, esp
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 3178496
}