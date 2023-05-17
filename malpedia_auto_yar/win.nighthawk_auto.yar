rule win_nighthawk_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.nighthawk."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nighthawk"
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
        $sequence_0 = { b938000000 e8???????? 488900 48894008 48894708 488d4f18 }
            // n = 6, score = 100
            //   b938000000           | dec                 ax
            //   e8????????           |                     
            //   488900               | movd                eax, mm0
            //   48894008             | dec                 esp
            //   48894708             | lea                 ecx, [0x1a1ed]
            //   488d4f18             | dec                 eax

        $sequence_1 = { 90 488bd0 488bcb e8???????? 488bc8 e8???????? 8bd8 }
            // n = 7, score = 100
            //   90                   | dec                 eax
            //   488bd0               | mov                 dword ptr [esp + 0x70], 0xf
            //   488bcb               | inc                 esp
            //   e8????????           |                     
            //   488bc8               | lea                 eax, [eax + 0x15]
            //   e8????????           |                     
            //   8bd8                 | dec                 eax

        $sequence_2 = { 4c89742450 4c89742460 4889742468 448d4315 488d150abf0700 488d4c2450 e8???????? }
            // n = 7, score = 100
            //   4c89742450           | dec                 esp
            //   4c89742460           | mov                 dword ptr [ebp + 0x188], edi
            //   4889742468           | inc                 esp
            //   448d4315             | mov                 byte ptr [ebp + 0x170], dh
            //   488d150abf0700       | dec                 eax
            //   488d4c2450           | mov                 ecx, dword ptr [ebp + 0x170]
            //   e8????????           |                     

        $sequence_3 = { ff15???????? 85c0 0f84f4000000 8b4d67 e8???????? 8b7d67 4c8d7668 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | dec                 ecx
            //   0f84f4000000         | mov                 ecx, esp
            //   8b4d67               | je                  0x14b7
            //   e8????????           |                     
            //   8b7d67               | dec                 eax
            //   4c8d7668             | lea                 edx, [ebx + 0xc8]

        $sequence_4 = { 720f 488b4df7 4885c9 7406 e8???????? 90 488b4d6f }
            // n = 7, score = 100
            //   720f                 | dec                 eax
            //   488b4df7             | mov                 ecx, eax
            //   4885c9               | nop                 
            //   7406                 | dec                 eax
            //   e8????????           |                     
            //   90                   | cmp                 dword ptr [ebp + 0x68], 0x10
            //   488b4d6f             | dec                 eax

        $sequence_5 = { 89442428 48894c2420 448b4d7f 4c8d45e7 33d2 488b4d97 ff15???????? }
            // n = 7, score = 100
            //   89442428             | imul                ecx
            //   48894c2420           | dec                 esp
            //   448b4d7f             | mov                 esi, edx
            //   4c8d45e7             | dec                 ecx
            //   33d2                 | sar                 esi, 4
            //   488b4d97             | dec                 ecx
            //   ff15????????         |                     

        $sequence_6 = { 7409 ff15???????? 8b4510 8983a8000000 85c0 741d 488bcb }
            // n = 7, score = 100
            //   7409                 | dec                 eax
            //   ff15????????         |                     
            //   8b4510               | mov                 eax, ebx
            //   8983a8000000         | dec                 eax
            //   85c0                 | lea                 edx, [ebx + 8]
            //   741d                 | dec                 eax
            //   488bcb               | lea                 ecx, [esp + 0x28]

        $sequence_7 = { 7203 488b00 41b806000000 488bd0 488bcb e8???????? 85c0 }
            // n = 7, score = 100
            //   7203                 | lea                 eax, [ebx - 8]
            //   488b00               | dec                 eax
            //   41b806000000         | cmp                 eax, 0x1f
            //   488bd0               | ja                  0xf2e
            //   488bcb               | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 ebx, ecx

        $sequence_8 = { ff15???????? e8???????? 488d0de3590800 4883c428 48ff25???????? 488bc4 48895808 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   e8????????           |                     
            //   488d0de3590800       | mov                 ebp, esi
            //   4883c428             | dec                 eax
            //   48ff25????????       |                     
            //   488bc4               | mov                 esi, dword ptr [esi]
            //   48895808             | je                  0x176d

        $sequence_9 = { ff15???????? 85c0 0f8807090000 488d8510120000 4889442420 41b938000000 4c8d8520010000 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | pop                 ebp
            //   0f8807090000         | ret                 
            //   488d8510120000       | je                  0x163b
            //   4889442420           | and                 dword ptr [ebp + 0x140], 0xfffffffd
            //   41b938000000         | dec                 eax
            //   4c8d8520010000       | lea                 ecx, [ebp + 0x80]

    condition:
        7 of them and filesize < 1949696
}