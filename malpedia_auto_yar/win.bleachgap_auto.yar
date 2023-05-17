rule win_bleachgap_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.bleachgap."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bleachgap"
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
        $sequence_0 = { c1f902 8b0c88 8d7604 8bc1 884efa c1e808 83c304 }
            // n = 7, score = 100
            //   c1f902               | sar                 ecx, 2
            //   8b0c88               | mov                 ecx, dword ptr [eax + ecx*4]
            //   8d7604               | lea                 esi, [esi + 4]
            //   8bc1                 | mov                 eax, ecx
            //   884efa               | mov                 byte ptr [esi - 6], cl
            //   c1e808               | shr                 eax, 8
            //   83c304               | add                 ebx, 4

        $sequence_1 = { 8b00 83452004 99 8bd8 8b442420 50 57 }
            // n = 7, score = 100
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   83452004             | add                 dword ptr [ebp + 0x20], 4
            //   99                   | cdq                 
            //   8bd8                 | mov                 ebx, eax
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_2 = { e8???????? 83c40c 85c0 0f85f6feffff 5f 5e 5d }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f85f6feffff         | jne                 0xfffffefc
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_3 = { 8d5b08 8b4a04 c70200000000 c7420400000000 83c208 8943f8 894bfc }
            // n = 7, score = 100
            //   8d5b08               | lea                 ebx, [ebx + 8]
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]
            //   c70200000000         | mov                 dword ptr [edx], 0
            //   c7420400000000       | mov                 dword ptr [edx + 4], 0
            //   83c208               | add                 edx, 8
            //   8943f8               | mov                 dword ptr [ebx - 8], eax
            //   894bfc               | mov                 dword ptr [ebx - 4], ecx

        $sequence_4 = { c3 8b54242c 49 55 57 8b7804 894c2414 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   49                   | dec                 ecx
            //   55                   | push                ebp
            //   57                   | push                edi
            //   8b7804               | mov                 edi, dword ptr [eax + 4]
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx

        $sequence_5 = { e8???????? 8bf0 83c408 85f6 7521 68b8000000 68???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8
            //   85f6                 | test                esi, esi
            //   7521                 | jne                 0x23
            //   68b8000000           | push                0xb8
            //   68????????           |                     

        $sequence_6 = { ff742420 57 e8???????? 83c410 85c0 0f84f0000000 833b00 }
            // n = 7, score = 100
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   0f84f0000000         | je                  0xf6
            //   833b00               | cmp                 dword ptr [ebx], 0

        $sequence_7 = { f6c208 7513 8a11 8855ff 80fa28 8b5350 7417 }
            // n = 7, score = 100
            //   f6c208               | test                dl, 8
            //   7513                 | jne                 0x15
            //   8a11                 | mov                 dl, byte ptr [ecx]
            //   8855ff               | mov                 byte ptr [ebp - 1], dl
            //   80fa28               | cmp                 dl, 0x28
            //   8b5350               | mov                 edx, dword ptr [ebx + 0x50]
            //   7417                 | je                  0x19

        $sequence_8 = { c7430400000000 c7430800000000 8b7004 2b30 c1fe02 85f6 743e }
            // n = 7, score = 100
            //   c7430400000000       | mov                 dword ptr [ebx + 4], 0
            //   c7430800000000       | mov                 dword ptr [ebx + 8], 0
            //   8b7004               | mov                 esi, dword ptr [eax + 4]
            //   2b30                 | sub                 esi, dword ptr [eax]
            //   c1fe02               | sar                 esi, 2
            //   85f6                 | test                esi, esi
            //   743e                 | je                  0x40

        $sequence_9 = { c1cd0c 03cd 03ca 8b54241c 894c2420 33cb c1c908 }
            // n = 7, score = 100
            //   c1cd0c               | ror                 ebp, 0xc
            //   03cd                 | add                 ecx, ebp
            //   03ca                 | add                 ecx, edx
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]
            //   894c2420             | mov                 dword ptr [esp + 0x20], ecx
            //   33cb                 | xor                 ecx, ebx
            //   c1c908               | ror                 ecx, 8

    condition:
        7 of them and filesize < 4538368
}