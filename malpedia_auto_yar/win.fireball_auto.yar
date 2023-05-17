rule win_fireball_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.fireball."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fireball"
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
        $sequence_0 = { 668944240c 7228 8bb424fc000000 8d4c240b e8???????? 51 }
            // n = 6, score = 100
            //   668944240c           | mov                 word ptr [esp + 0xc], ax
            //   7228                 | jb                  0x2a
            //   8bb424fc000000       | mov                 esi, dword ptr [esp + 0xfc]
            //   8d4c240b             | lea                 ecx, [esp + 0xb]
            //   e8????????           |                     
            //   51                   | push                ecx

        $sequence_1 = { 50 ff15???????? 8bf8 89bd1cf6ffff 85ff }
            // n = 5, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   89bd1cf6ffff         | mov                 dword ptr [ebp - 0x9e4], edi
            //   85ff                 | test                edi, edi

        $sequence_2 = { 59 817e5cf87f2400 7409 ff765c e8???????? 59 6a0d }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   817e5cf87f2400       | cmp                 dword ptr [esi + 0x5c], 0x247ff8
            //   7409                 | je                  0xb
            //   ff765c               | push                dword ptr [esi + 0x5c]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   6a0d                 | push                0xd

        $sequence_3 = { 720b ff75b0 e8???????? 83c404 83bd6cfbffff10 8d9558fbffff }
            // n = 6, score = 100
            //   720b                 | jb                  0xd
            //   ff75b0               | push                dword ptr [ebp - 0x50]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83bd6cfbffff10       | cmp                 dword ptr [ebp - 0x494], 0x10
            //   8d9558fbffff         | lea                 edx, [ebp - 0x4a8]

        $sequence_4 = { 85c0 7810 3de4000000 7309 8b04c558812400 5d }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7810                 | js                  0x12
            //   3de4000000           | cmp                 eax, 0xe4
            //   7309                 | jae                 0xb
            //   8b04c558812400       | mov                 eax, dword ptr [eax*8 + 0x248158]
            //   5d                   | pop                 ebp

        $sequence_5 = { c645fc16 e8???????? 68???????? 8bd0 8d8d04f5ffff c645fc17 e8???????? }
            // n = 7, score = 100
            //   c645fc16             | mov                 byte ptr [ebp - 4], 0x16
            //   e8????????           |                     
            //   68????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d8d04f5ffff         | lea                 ecx, [ebp - 0xafc]
            //   c645fc17             | mov                 byte ptr [ebp - 4], 0x17
            //   e8????????           |                     

        $sequence_6 = { 68???????? 8d8c2404010000 c784241801000007000000 c784241401000000000000 6689842404010000 e8???????? c78424f801000000000000 }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d8c2404010000       | lea                 ecx, [esp + 0x104]
            //   c784241801000007000000     | mov    dword ptr [esp + 0x118], 7
            //   c784241401000000000000     | mov    dword ptr [esp + 0x114], 0
            //   6689842404010000     | mov                 word ptr [esp + 0x104], ax
            //   e8????????           |                     
            //   c78424f801000000000000     | mov    dword ptr [esp + 0x1f8], 0

        $sequence_7 = { 8b0c85000a2500 8a06 88441926 46 2bf2 eb14 f7da }
            // n = 7, score = 100
            //   8b0c85000a2500       | mov                 ecx, dword ptr [eax*4 + 0x250a00]
            //   8a06                 | mov                 al, byte ptr [esi]
            //   88441926             | mov                 byte ptr [ecx + ebx + 0x26], al
            //   46                   | inc                 esi
            //   2bf2                 | sub                 esi, edx
            //   eb14                 | jmp                 0x16
            //   f7da                 | neg                 edx

        $sequence_8 = { 0f43c6 66833c4841 722e 83fa08 b8???????? 0f43c6 }
            // n = 6, score = 100
            //   0f43c6               | cmovae              eax, esi
            //   66833c4841           | cmp                 word ptr [eax + ecx*2], 0x41
            //   722e                 | jb                  0x30
            //   83fa08               | cmp                 edx, 8
            //   b8????????           |                     
            //   0f43c6               | cmovae              eax, esi

        $sequence_9 = { 64a300000000 6a01 33c0 68???????? 8d8c2404010000 c784241801000007000000 c784241401000000000000 }
            // n = 7, score = 100
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   6a01                 | push                1
            //   33c0                 | xor                 eax, eax
            //   68????????           |                     
            //   8d8c2404010000       | lea                 ecx, [esp + 0x104]
            //   c784241801000007000000     | mov    dword ptr [esp + 0x118], 7
            //   c784241401000000000000     | mov    dword ptr [esp + 0x114], 0

    condition:
        7 of them and filesize < 335872
}