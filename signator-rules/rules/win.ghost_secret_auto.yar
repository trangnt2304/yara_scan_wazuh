rule win_ghost_secret_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.ghost_secret."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ghost_secret"
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
        $sequence_0 = { c644243007 c6442431fd c64424322c c644243335 c6442434d9 c6442435f4 }
            // n = 6, score = 200
            //   c644243007           | mov                 byte ptr [esp + 0x30], 7
            //   c6442431fd           | mov                 byte ptr [esp + 0x31], 0xfd
            //   c64424322c           | mov                 byte ptr [esp + 0x32], 0x2c
            //   c644243335           | mov                 byte ptr [esp + 0x33], 0x35
            //   c6442434d9           | mov                 byte ptr [esp + 0x34], 0xd9
            //   c6442435f4           | mov                 byte ptr [esp + 0x35], 0xf4

        $sequence_1 = { c64424513e c644245260 c644245c7a c644245d76 c644245e77 c644245f76 c64424607e }
            // n = 7, score = 200
            //   c64424513e           | mov                 byte ptr [esp + 0x51], 0x3e
            //   c644245260           | mov                 byte ptr [esp + 0x52], 0x60
            //   c644245c7a           | mov                 byte ptr [esp + 0x5c], 0x7a
            //   c644245d76           | mov                 byte ptr [esp + 0x5d], 0x76
            //   c644245e77           | mov                 byte ptr [esp + 0x5e], 0x77
            //   c644245f76           | mov                 byte ptr [esp + 0x5f], 0x76
            //   c64424607e           | mov                 byte ptr [esp + 0x60], 0x7e

        $sequence_2 = { 751c 56 ff15???????? 8b542404 52 ff15???????? 33c0 }
            // n = 7, score = 200
            //   751c                 | jne                 0x1e
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { 8aa8c4df4100 8bc2 c1e818 0fb680c4df4100 33c8 33c0 8a4512 }
            // n = 7, score = 200
            //   8aa8c4df4100         | mov                 ch, byte ptr [eax + 0x41dfc4]
            //   8bc2                 | mov                 eax, edx
            //   c1e818               | shr                 eax, 0x18
            //   0fb680c4df4100       | movzx               eax, byte ptr [eax + 0x41dfc4]
            //   33c8                 | xor                 ecx, eax
            //   33c0                 | xor                 eax, eax
            //   8a4512               | mov                 al, byte ptr [ebp + 0x12]

        $sequence_4 = { c684248b000000c3 c684248c00000012 c684248d0000001f c684248e000000ac c684248f0000003f c6842490000000cf }
            // n = 6, score = 200
            //   c684248b000000c3     | mov                 byte ptr [esp + 0x8b], 0xc3
            //   c684248c00000012     | mov                 byte ptr [esp + 0x8c], 0x12
            //   c684248d0000001f     | mov                 byte ptr [esp + 0x8d], 0x1f
            //   c684248e000000ac     | mov                 byte ptr [esp + 0x8e], 0xac
            //   c684248f0000003f     | mov                 byte ptr [esp + 0x8f], 0x3f
            //   c6842490000000cf     | mov                 byte ptr [esp + 0x90], 0xcf

        $sequence_5 = { 8d8424c40a0000 50 e8???????? 8b0d???????? 8b942470020000 8d744604 }
            // n = 6, score = 200
            //   8d8424c40a0000       | lea                 eax, [esp + 0xac4]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b0d????????         |                     
            //   8b942470020000       | mov                 edx, dword ptr [esp + 0x270]
            //   8d744604             | lea                 esi, [esi + eax*2 + 4]

        $sequence_6 = { 8884249e010000 c684249f0100002f c68424a001000011 889c24a1010000 }
            // n = 4, score = 200
            //   8884249e010000       | mov                 byte ptr [esp + 0x19e], al
            //   c684249f0100002f     | mov                 byte ptr [esp + 0x19f], 0x2f
            //   c68424a001000011     | mov                 byte ptr [esp + 0x1a0], 0x11
            //   889c24a1010000       | mov                 byte ptr [esp + 0x1a1], bl

        $sequence_7 = { ff15???????? 8d9424a4030000 6a0f 52 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   8d9424a4030000       | lea                 edx, [esp + 0x3a4]
            //   6a0f                 | push                0xf
            //   52                   | push                edx

        $sequence_8 = { c6842423070000b7 c6842424070000da c6842425070000aa c68424260700007f c6842427070000bb c684242807000035 c68424b80700004b }
            // n = 7, score = 200
            //   c6842423070000b7     | mov                 byte ptr [esp + 0x723], 0xb7
            //   c6842424070000da     | mov                 byte ptr [esp + 0x724], 0xda
            //   c6842425070000aa     | mov                 byte ptr [esp + 0x725], 0xaa
            //   c68424260700007f     | mov                 byte ptr [esp + 0x726], 0x7f
            //   c6842427070000bb     | mov                 byte ptr [esp + 0x727], 0xbb
            //   c684242807000035     | mov                 byte ptr [esp + 0x728], 0x35
            //   c68424b80700004b     | mov                 byte ptr [esp + 0x7b8], 0x4b

        $sequence_9 = { 889424f6050000 c68424f70500004c c68424f805000074 c68424f90500007e c68424fa05000064 c68424fb05000047 }
            // n = 6, score = 200
            //   889424f6050000       | mov                 byte ptr [esp + 0x5f6], dl
            //   c68424f70500004c     | mov                 byte ptr [esp + 0x5f7], 0x4c
            //   c68424f805000074     | mov                 byte ptr [esp + 0x5f8], 0x74
            //   c68424f90500007e     | mov                 byte ptr [esp + 0x5f9], 0x7e
            //   c68424fa05000064     | mov                 byte ptr [esp + 0x5fa], 0x64
            //   c68424fb05000047     | mov                 byte ptr [esp + 0x5fb], 0x47

    condition:
        7 of them and filesize < 278528
}