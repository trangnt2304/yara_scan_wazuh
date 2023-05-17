rule win_cinobi_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.cinobi."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cinobi"
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
        $sequence_0 = { c9 c3 55 8bec 51 e8???????? 58 }
            // n = 7, score = 200
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   e8????????           |                     
            //   58                   | pop                 eax

        $sequence_1 = { ff75fc e8???????? 83c448 ff765f 8986c3000000 ffb6c7000000 ff75fc }
            // n = 7, score = 100
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   83c448               | add                 esp, 0x48
            //   ff765f               | push                dword ptr [esi + 0x5f]
            //   8986c3000000         | mov                 dword ptr [esi + 0xc3], eax
            //   ffb6c7000000         | push                dword ptr [esi + 0xc7]
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_2 = { 8b85a8faffff 660fbe00 66898534fdffff 8b85a8faffff }
            // n = 4, score = 100
            //   8b85a8faffff         | mov                 eax, dword ptr [ebp - 0x558]
            //   660fbe00             | movsx               ax, byte ptr [eax]
            //   66898534fdffff       | mov                 word ptr [ebp - 0x2cc], ax
            //   8b85a8faffff         | mov                 eax, dword ptr [ebp - 0x558]

        $sequence_3 = { b878440700 0345fc 8945f8 6880000000 }
            // n = 4, score = 100
            //   b878440700           | mov                 eax, 0x74478
            //   0345fc               | add                 eax, dword ptr [ebp - 4]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   6880000000           | push                0x80

        $sequence_4 = { 88442423 8a4646 88442424 8a4654 88442425 }
            // n = 5, score = 100
            //   88442423             | mov                 byte ptr [esp + 0x23], al
            //   8a4646               | mov                 al, byte ptr [esi + 0x46]
            //   88442424             | mov                 byte ptr [esp + 0x24], al
            //   8a4654               | mov                 al, byte ptr [esi + 0x54]
            //   88442425             | mov                 byte ptr [esp + 0x25], al

        $sequence_5 = { 7552 c745e810000000 6a00 ff7510 ff750c ff75ec 8b45f8 }
            // n = 7, score = 100
            //   7552                 | jne                 0x54
            //   c745e810000000       | mov                 dword ptr [ebp - 0x18], 0x10
            //   6a00                 | push                0
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_6 = { 8844242d 8a464b 88842438010000 8a4605 88842439010000 }
            // n = 5, score = 100
            //   8844242d             | mov                 byte ptr [esp + 0x2d], al
            //   8a464b               | mov                 al, byte ptr [esi + 0x4b]
            //   88842438010000       | mov                 byte ptr [esp + 0x138], al
            //   8a4605               | mov                 al, byte ptr [esi + 5]
            //   88842439010000       | mov                 byte ptr [esp + 0x139], al

        $sequence_7 = { 8d8574fdffff 50 ff939f000000 6a02 }
            // n = 4, score = 100
            //   8d8574fdffff         | lea                 eax, [ebp - 0x28c]
            //   50                   | push                eax
            //   ff939f000000         | call                dword ptr [ebx + 0x9f]
            //   6a02                 | push                2

        $sequence_8 = { 66898f921c0000 660fbe4e4f 66898f941c0000 660fbe4e13 66898f961c0000 660fbe4e19 }
            // n = 6, score = 100
            //   66898f921c0000       | mov                 word ptr [edi + 0x1c92], cx
            //   660fbe4e4f           | movsx               cx, byte ptr [esi + 0x4f]
            //   66898f941c0000       | mov                 word ptr [edi + 0x1c94], cx
            //   660fbe4e13           | movsx               cx, byte ptr [esi + 0x13]
            //   66898f961c0000       | mov                 word ptr [edi + 0x1c96], cx
            //   660fbe4e19           | movsx               cx, byte ptr [esi + 0x19]

        $sequence_9 = { 57 ff96e7000000 83c40c eb14 ff750c 8d45e0 ff7508 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   ff96e7000000         | call                dword ptr [esi + 0xe7]
            //   83c40c               | add                 esp, 0xc
            //   eb14                 | jmp                 0x16
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_10 = { 8845ed 8b45dc 8a4005 8845ee 8b45dc 8a404e }
            // n = 6, score = 100
            //   8845ed               | mov                 byte ptr [ebp - 0x13], al
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8a4005               | mov                 al, byte ptr [eax + 5]
            //   8845ee               | mov                 byte ptr [ebp - 0x12], al
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8a404e               | mov                 al, byte ptr [eax + 0x4e]

        $sequence_11 = { 8a4034 8845c9 8b45c0 8a4004 8845ca 8b45c0 }
            // n = 6, score = 100
            //   8a4034               | mov                 al, byte ptr [eax + 0x34]
            //   8845c9               | mov                 byte ptr [ebp - 0x37], al
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   8a4004               | mov                 al, byte ptr [eax + 4]
            //   8845ca               | mov                 byte ptr [ebp - 0x36], al
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]

        $sequence_12 = { 51 57 8d8e6e020000 51 50 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8d8e6e020000         | lea                 ecx, [esi + 0x26e]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_13 = { 8b45c0 8a4004 8845a3 8b45c0 8a00 }
            // n = 5, score = 100
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   8a4004               | mov                 al, byte ptr [eax + 4]
            //   8845a3               | mov                 byte ptr [ebp - 0x5d], al
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   8a00                 | mov                 al, byte ptr [eax]

        $sequence_14 = { 6689856afbffff 8b45f8 660fbe00 6689856cfbffff 8b45f8 660fbe4003 6689856efbffff }
            // n = 7, score = 100
            //   6689856afbffff       | mov                 word ptr [ebp - 0x496], ax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   660fbe00             | movsx               ax, byte ptr [eax]
            //   6689856cfbffff       | mov                 word ptr [ebp - 0x494], ax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   660fbe4003           | movsx               ax, byte ptr [eax + 3]
            //   6689856efbffff       | mov                 word ptr [ebp - 0x492], ax

    condition:
        7 of them and filesize < 32768
}