rule win_zeus_mailsniffer_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.zeus_mailsniffer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus_mailsniffer"
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
        $sequence_0 = { ff742410 ffd6 ff742420 ffd6 57 ffd6 ff742418 }
            // n = 7, score = 100
            //   ff742410             | push                dword ptr [esp + 0x10]
            //   ffd6                 | call                esi
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   ffd6                 | call                esi
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   ff742418             | push                dword ptr [esp + 0x18]

        $sequence_1 = { 6a0b e8???????? 83c40c 85c0 7417 ff7508 }
            // n = 6, score = 100
            //   6a0b                 | push                0xb
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   7417                 | je                  0x19
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_2 = { 66837ddc00 8b87a0902d01 7403 6a29 58 8d8dd4fdffff 51 }
            // n = 7, score = 100
            //   66837ddc00           | cmp                 word ptr [ebp - 0x24], 0
            //   8b87a0902d01         | mov                 eax, dword ptr [edi + 0x12d90a0]
            //   7403                 | je                  5
            //   6a29                 | push                0x29
            //   58                   | pop                 eax
            //   8d8dd4fdffff         | lea                 ecx, [ebp - 0x22c]
            //   51                   | push                ecx

        $sequence_3 = { 8505???????? 745c 8d45e0 50 6800000040 ff75f4 }
            // n = 6, score = 100
            //   8505????????         |                     
            //   745c                 | je                  0x5e
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   6800000040           | push                0x40000000
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_4 = { 8b47f0 8bf0 c1ee0a 83e608 8975cc a803 }
            // n = 6, score = 100
            //   8b47f0               | mov                 eax, dword ptr [edi - 0x10]
            //   8bf0                 | mov                 esi, eax
            //   c1ee0a               | shr                 esi, 0xa
            //   83e608               | and                 esi, 8
            //   8975cc               | mov                 dword ptr [ebp - 0x34], esi
            //   a803                 | test                al, 3

        $sequence_5 = { 895df0 c7459401000000 895d98 895d9c 895da0 ffd7 }
            // n = 6, score = 100
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   c7459401000000       | mov                 dword ptr [ebp - 0x6c], 1
            //   895d98               | mov                 dword ptr [ebp - 0x68], ebx
            //   895d9c               | mov                 dword ptr [ebp - 0x64], ebx
            //   895da0               | mov                 dword ptr [ebp - 0x60], ebx
            //   ffd7                 | call                edi

        $sequence_6 = { 0f8427010000 ff15???????? 83f87a 0f8418010000 }
            // n = 4, score = 100
            //   0f8427010000         | je                  0x12d
            //   ff15????????         |                     
            //   83f87a               | cmp                 eax, 0x7a
            //   0f8418010000         | je                  0x11e

        $sequence_7 = { 5e 8be5 5d c3 0fb7c0 8d04c5208d2d01 33d2 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   0fb7c0               | movzx               eax, ax
            //   8d04c5208d2d01       | lea                 eax, [eax*8 + 0x12d8d20]
            //   33d2                 | xor                 edx, edx

        $sequence_8 = { c1e710 e8???????? 0fb7c0 0bc7 8945a6 8d8534faffff 50 }
            // n = 7, score = 100
            //   c1e710               | shl                 edi, 0x10
            //   e8????????           |                     
            //   0fb7c0               | movzx               eax, ax
            //   0bc7                 | or                  eax, edi
            //   8945a6               | mov                 dword ptr [ebp - 0x5a], eax
            //   8d8534faffff         | lea                 eax, [ebp - 0x5cc]
            //   50                   | push                eax

        $sequence_9 = { 83f8ff 0f84a7010000 53 83c8ff 8bd7 e8???????? }
            // n = 6, score = 100
            //   83f8ff               | cmp                 eax, -1
            //   0f84a7010000         | je                  0x1ad
            //   53                   | push                ebx
            //   83c8ff               | or                  eax, 0xffffffff
            //   8bd7                 | mov                 edx, edi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 368640
}