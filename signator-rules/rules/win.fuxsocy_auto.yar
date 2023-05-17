rule win_fuxsocy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.fuxsocy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fuxsocy"
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
        $sequence_0 = { 6a08 5a 8bce 89742414 e8???????? 8bf8 }
            // n = 6, score = 200
            //   6a08                 | push                8
            //   5a                   | pop                 edx
            //   8bce                 | mov                 ecx, esi
            //   89742414             | mov                 dword ptr [esp + 0x14], esi
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_1 = { 50 c745c03c000000 c745c400c60000 c745cc989f4000 c745d080944000 897ddc ff15???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   c745c03c000000       | mov                 dword ptr [ebp - 0x40], 0x3c
            //   c745c400c60000       | mov                 dword ptr [ebp - 0x3c], 0xc600
            //   c745cc989f4000       | mov                 dword ptr [ebp - 0x34], 0x409f98
            //   c745d080944000       | mov                 dword ptr [ebp - 0x30], 0x409480
            //   897ddc               | mov                 dword ptr [ebp - 0x24], edi
            //   ff15????????         |                     

        $sequence_2 = { 0bfe b9ff000000 c1e708 e8???????? 8b4c244c 0fb6c0 0bc7 }
            // n = 7, score = 200
            //   0bfe                 | or                  edi, esi
            //   b9ff000000           | mov                 ecx, 0xff
            //   c1e708               | shl                 edi, 8
            //   e8????????           |                     
            //   8b4c244c             | mov                 ecx, dword ptr [esp + 0x4c]
            //   0fb6c0               | movzx               eax, al
            //   0bc7                 | or                  eax, edi

        $sequence_3 = { 53 55 57 8bea 8bf9 33db }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   57                   | push                edi
            //   8bea                 | mov                 ebp, edx
            //   8bf9                 | mov                 edi, ecx
            //   33db                 | xor                 ebx, ebx

        $sequence_4 = { 8b4c2440 8b542444 8bc1 2b05???????? 8bfb 89442424 8bc2 }
            // n = 7, score = 200
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   8b542444             | mov                 edx, dword ptr [esp + 0x44]
            //   8bc1                 | mov                 eax, ecx
            //   2b05????????         |                     
            //   8bfb                 | mov                 edi, ebx
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   8bc2                 | mov                 eax, edx

        $sequence_5 = { 55 8bec 83ec0c 53 56 32db }
            // n = 6, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec0c               | sub                 esp, 0xc
            //   53                   | push                ebx
            //   56                   | push                esi
            //   32db                 | xor                 bl, bl

        $sequence_6 = { e8???????? c605????????01 ff35???????? ff15???????? 5f 5e 5b }
            // n = 7, score = 200
            //   e8????????           |                     
            //   c605????????01       |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_7 = { ff15???????? ff74242c 53 ff15???????? 56 ff15???????? 53 }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   53                   | push                ebx

        $sequence_8 = { 8364241c00 8364242800 8364242c00 8d442410 89442420 8d442418 }
            // n = 6, score = 200
            //   8364241c00           | and                 dword ptr [esp + 0x1c], 0
            //   8364242800           | and                 dword ptr [esp + 0x28], 0
            //   8364242c00           | and                 dword ptr [esp + 0x2c], 0
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   8d442418             | lea                 eax, [esp + 0x18]

        $sequence_9 = { 8bec 51 53 56 57 33d2 b9???????? }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   33d2                 | xor                 edx, edx
            //   b9????????           |                     

    condition:
        7 of them and filesize < 131072
}