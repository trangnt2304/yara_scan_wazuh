rule win_eternal_petya_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.eternal_petya."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eternal_petya"
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
        $sequence_0 = { 49 75f9 56 ff15???????? }
            // n = 4, score = 400
            //   49                   | dec                 ecx
            //   75f9                 | jne                 0xfffffffb
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_1 = { 53 68f0000000 6a40 ff15???????? 8bd8 }
            // n = 5, score = 400
            //   53                   | push                ebx
            //   68f0000000           | push                0xf0
            //   6a40                 | push                0x40
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_2 = { 55 8bec 51 57 68000000f0 6a18 33ff }
            // n = 7, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   57                   | push                edi
            //   68000000f0           | push                0xf0000000
            //   6a18                 | push                0x18
            //   33ff                 | xor                 edi, edi

        $sequence_3 = { 53 8d4644 50 53 6a02 }
            // n = 5, score = 400
            //   53                   | push                ebx
            //   8d4644               | lea                 eax, [esi + 0x44]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   6a02                 | push                2

        $sequence_4 = { 53 6a21 8d460c 50 }
            // n = 4, score = 400
            //   53                   | push                ebx
            //   6a21                 | push                0x21
            //   8d460c               | lea                 eax, [esi + 0xc]
            //   50                   | push                eax

        $sequence_5 = { 55 8bec 83ec50 53 68???????? }
            // n = 5, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec50               | sub                 esp, 0x50
            //   53                   | push                ebx
            //   68????????           |                     

        $sequence_6 = { 55 8bec 83ec7c 33c0 33d2 }
            // n = 5, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec7c               | sub                 esp, 0x7c
            //   33c0                 | xor                 eax, eax
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 33db 53 33ff 53 }
            // n = 4, score = 300
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx
            //   33ff                 | xor                 edi, edi
            //   53                   | push                ebx

        $sequence_8 = { 55 8bec 8b4508 85c0 741a 8b481c }
            // n = 6, score = 300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   85c0                 | test                eax, eax
            //   741a                 | je                  0x1c
            //   8b481c               | mov                 ecx, dword ptr [eax + 0x1c]

        $sequence_9 = { 03c8 8bc2 c1e818 03c8 33c0 }
            // n = 5, score = 300
            //   03c8                 | add                 ecx, eax
            //   8bc2                 | mov                 eax, edx
            //   c1e818               | shr                 eax, 0x18
            //   03c8                 | add                 ecx, eax
            //   33c0                 | xor                 eax, eax

        $sequence_10 = { 33db 47 395e34 7520 }
            // n = 4, score = 300
            //   33db                 | xor                 ebx, ebx
            //   47                   | inc                 edi
            //   395e34               | cmp                 dword ptr [esi + 0x34], ebx
            //   7520                 | jne                 0x22

        $sequence_11 = { 33db 50 53 33ff 895df8 }
            // n = 5, score = 300
            //   33db                 | xor                 ebx, ebx
            //   50                   | push                eax
            //   53                   | push                ebx
            //   33ff                 | xor                 edi, edi
            //   895df8               | mov                 dword ptr [ebp - 8], ebx

        $sequence_12 = { 33db 53 53 6aff ff7508 bfe9fd0000 }
            // n = 6, score = 300
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   6aff                 | push                -1
            //   ff7508               | push                dword ptr [ebp + 8]
            //   bfe9fd0000           | mov                 edi, 0xfde9

        $sequence_13 = { 8b7008 57 33db 53 }
            // n = 4, score = 200
            //   8b7008               | mov                 esi, dword ptr [eax + 8]
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx

        $sequence_14 = { 8b7008 57 8b7d18 6a00 }
            // n = 4, score = 200
            //   8b7008               | mov                 esi, dword ptr [eax + 8]
            //   57                   | push                edi
            //   8b7d18               | mov                 edi, dword ptr [ebp + 0x18]
            //   6a00                 | push                0

        $sequence_15 = { 8bf8 eb3f 688c000000 50 }
            // n = 4, score = 200
            //   8bf8                 | mov                 edi, eax
            //   eb3f                 | jmp                 0x41
            //   688c000000           | push                0x8c
            //   50                   | push                eax

    condition:
        7 of them and filesize < 851968
}