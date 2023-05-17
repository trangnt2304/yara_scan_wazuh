rule win_vobfus_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.vobfus."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vobfus"
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
        $sequence_0 = { 8b8258040000 50 50 8b10 ff5204 58 }
            // n = 6, score = 200
            //   8b8258040000         | mov                 eax, dword ptr [edx + 0x458]
            //   50                   | push                eax
            //   50                   | push                eax
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   ff5204               | call                dword ptr [edx + 4]
            //   58                   | pop                 eax

        $sequence_1 = { 8b5508 8b92e8000000 8b82840b0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82840b0000         | mov                 eax, dword ptr [edx + 0xb84]
            //   50                   | push                eax

        $sequence_2 = { 8b5508 8b92e8000000 8b8274180000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8274180000         | mov                 eax, dword ptr [edx + 0x1874]
            //   50                   | push                eax

        $sequence_3 = { 8b5508 8b92e8000000 8b82141e0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82141e0000         | mov                 eax, dword ptr [edx + 0x1e14]
            //   50                   | push                eax

        $sequence_4 = { 8b5508 8b92e8000000 8b8230170000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8230170000         | mov                 eax, dword ptr [edx + 0x1730]
            //   50                   | push                eax

        $sequence_5 = { 8b5508 8b92e8000000 8b82740f0000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b82740f0000         | mov                 eax, dword ptr [edx + 0xf74]
            //   50                   | push                eax

        $sequence_6 = { 8b5508 8b92e8000000 8b8290080000 50 }
            // n = 4, score = 200
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8290080000         | mov                 eax, dword ptr [edx + 0x890]
            //   50                   | push                eax

        $sequence_7 = { 55 8bec 8b5508 8b92e8000000 8b8238150000 50 50 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b92e8000000         | mov                 edx, dword ptr [edx + 0xe8]
            //   8b8238150000         | mov                 eax, dword ptr [edx + 0x1538]
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_8 = { d2b5f2bb8ff3 ae 73f3 aa }
            // n = 4, score = 100
            //   d2b5f2bb8ff3         | sal                 byte ptr [ebp - 0xc70440e], cl
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   73f3                 | jae                 0xfffffff5
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_9 = { 66f2eb32 8631 96 0a7f25 7a43 92 9afc9e5780451f }
            // n = 7, score = 100
            //   66f2eb32             | bnd jmp             0x36
            //   8631                 | xchg                byte ptr [ecx], dh
            //   96                   | xchg                eax, esi
            //   0a7f25               | or                  bh, byte ptr [edi + 0x25]
            //   7a43                 | jp                  0x45
            //   92                   | xchg                eax, edx
            //   9afc9e5780451f       | lcall               0x1f45:0x80579efc

        $sequence_10 = { a1???????? 00ec dea600e0d4b3 00e0 d4b4 }
            // n = 5, score = 100
            //   a1????????           |                     
            //   00ec                 | add                 ah, ch
            //   dea600e0d4b3         | fisub               word ptr [esi - 0x4c2b2000]
            //   00e0                 | add                 al, ah
            //   d4b4                 | aam                 0xb4

        $sequence_11 = { 7cc8 dc7acd e291 d2e8 }
            // n = 4, score = 100
            //   7cc8                 | jl                  0xffffffca
            //   dc7acd               | fdivr               qword ptr [edx - 0x33]
            //   e291                 | loop                0xffffff93
            //   d2e8                 | shr                 al, cl

        $sequence_12 = { 48 0008 78ff 0d50004900 3e3cff 46 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   0008                 | add                 byte ptr [eax], cl
            //   78ff                 | js                  1
            //   0d50004900           | or                  eax, 0x490050
            //   3e3cff               | cmp                 al, 0xff
            //   46                   | inc                 esi

        $sequence_13 = { f2ed ec f2ed ec f2ed }
            // n = 5, score = 100
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f2ed                 | in                  eax, dx

        $sequence_14 = { 06 95 1497 17 c1b8cc92aed3d4 9d 0e }
            // n = 7, score = 100
            //   06                   | push                es
            //   95                   | xchg                eax, ebp
            //   1497                 | adc                 al, 0x97
            //   17                   | pop                 ss
            //   c1b8cc92aed3d4       | sar                 dword ptr [eax - 0x2c516d34], 0xd4
            //   9d                   | popfd               
            //   0e                   | push                cs

        $sequence_15 = { 92 9afc9e5780451f 4a a1???????? 57 de0d???????? }
            // n = 6, score = 100
            //   92                   | xchg                eax, edx
            //   9afc9e5780451f       | lcall               0x1f45:0x80579efc
            //   4a                   | dec                 edx
            //   a1????????           |                     
            //   57                   | push                edi
            //   de0d????????         |                     

        $sequence_16 = { 73f3 aa 5c f6ac4ff8b54ffb c058fcca }
            // n = 5, score = 100
            //   73f3                 | jae                 0xfffffff5
            //   aa                   | stosb               byte ptr es:[edi], al
            //   5c                   | pop                 esp
            //   f6ac4ff8b54ffb       | imul                byte ptr [edi + ecx*2 - 0x4b04a08]
            //   c058fcca             | rcr                 byte ptr [eax - 4], 0xca

        $sequence_17 = { f2ed ec f3ed ebf2 ed }
            // n = 5, score = 100
            //   f2ed                 | in                  eax, dx
            //   ec                   | in                  al, dx
            //   f3ed                 | in                  eax, dx
            //   ebf2                 | jmp                 0xfffffff4
            //   ed                   | in                  eax, dx

        $sequence_18 = { 7d75 85783e d7 29ee 7ccb 59 b54a }
            // n = 7, score = 100
            //   7d75                 | jge                 0x77
            //   85783e               | test                dword ptr [eax + 0x3e], edi
            //   d7                   | xlatb               
            //   29ee                 | sub                 esi, ebp
            //   7ccb                 | jl                  0xffffffcd
            //   59                   | pop                 ecx
            //   b54a                 | mov                 ch, 0x4a

        $sequence_19 = { 94 e1ed 4b cf 1937 }
            // n = 5, score = 100
            //   94                   | xchg                eax, esp
            //   e1ed                 | loope               0xffffffef
            //   4b                   | dec                 ebx
            //   cf                   | iretd               
            //   1937                 | sbb                 dword ptr [edi], esi

        $sequence_20 = { 0d50004900 3e3cff 46 14ff 0470 fe0a }
            // n = 6, score = 100
            //   0d50004900           | or                  eax, 0x490050
            //   3e3cff               | cmp                 al, 0xff
            //   46                   | inc                 esi
            //   14ff                 | adc                 al, 0xff
            //   0470                 | add                 al, 0x70
            //   fe0a                 | dec                 byte ptr [edx]

        $sequence_21 = { 3401 41 06 1005???????? }
            // n = 4, score = 100
            //   3401                 | xor                 al, 1
            //   41                   | inc                 ecx
            //   06                   | push                es
            //   1005????????         |                     

        $sequence_22 = { 97 00e6 d39500e4d19b 00cf c0b200d1c3b600 e6d3 a1???????? }
            // n = 7, score = 100
            //   97                   | xchg                eax, edi
            //   00e6                 | add                 dh, ah
            //   d39500e4d19b         | rcl                 dword ptr [ebp - 0x642e1c00], cl
            //   00cf                 | add                 bh, cl
            //   c0b200d1c3b600       | sal                 byte ptr [edx - 0x493c2f00], 0
            //   e6d3                 | out                 0xd3, al
            //   a1????????           |                     

    condition:
        7 of them and filesize < 409600
}