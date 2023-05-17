rule win_void_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-03-28"
        version = "1"
        description = "Detects win.void."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.void"
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
        $sequence_0 = { 03d0 8b442434 33442414 8bca 3344241c 3344243c d1c0 }
            // n = 7, score = 200
            //   03d0                 | add                 edx, eax
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   33442414             | xor                 eax, dword ptr [esp + 0x14]
            //   8bca                 | mov                 ecx, edx
            //   3344241c             | xor                 eax, dword ptr [esp + 0x1c]
            //   3344243c             | xor                 eax, dword ptr [esp + 0x3c]
            //   d1c0                 | rol                 eax, 1

        $sequence_1 = { 8bc3 0faf442418 03e8 8d46ff 2bfb 7590 }
            // n = 6, score = 200
            //   8bc3                 | mov                 eax, ebx
            //   0faf442418           | imul                eax, dword ptr [esp + 0x18]
            //   03e8                 | add                 ebp, eax
            //   8d46ff               | lea                 eax, [esi - 1]
            //   2bfb                 | sub                 edi, ebx
            //   7590                 | jne                 0xffffff92

        $sequence_2 = { e9???????? 8d8d40ffffff e9???????? 8d8d68ffffff e9???????? 8d8d5cffffff e9???????? }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8d8d40ffffff         | lea                 ecx, [ebp - 0xc0]
            //   e9????????           |                     
            //   8d8d68ffffff         | lea                 ecx, [ebp - 0x98]
            //   e9????????           |                     
            //   8d8d5cffffff         | lea                 ecx, [ebp - 0xa4]
            //   e9????????           |                     

        $sequence_3 = { f30f7e45d0 8b45b8 660fd645e8 c645fc00 0f114dd8 85d2 0f8519ffffff }
            // n = 7, score = 200
            //   f30f7e45d0           | movq                xmm0, qword ptr [ebp - 0x30]
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   660fd645e8           | movq                qword ptr [ebp - 0x18], xmm0
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   0f114dd8             | movups              xmmword ptr [ebp - 0x28], xmm1
            //   85d2                 | test                edx, edx
            //   0f8519ffffff         | jne                 0xffffff1f

        $sequence_4 = { 8b4d80 8b450c 894110 8b45fc 894114 8bc7 895918 }
            // n = 7, score = 200
            //   8b4d80               | mov                 ecx, dword ptr [ebp - 0x80]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   894110               | mov                 dword ptr [ecx + 0x10], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   894114               | mov                 dword ptr [ecx + 0x14], eax
            //   8bc7                 | mov                 eax, edi
            //   895918               | mov                 dword ptr [ecx + 0x18], ebx

        $sequence_5 = { 8bc1 8b4c2440 5e 5d 33cc e8???????? 83c43c }
            // n = 7, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   33cc                 | xor                 ecx, esp
            //   e8????????           |                     
            //   83c43c               | add                 esp, 0x3c

        $sequence_6 = { e8???????? 8a45d7 83c408 84c0 0f8490000000 68???????? e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8a45d7               | mov                 al, byte ptr [ebp - 0x29]
            //   83c408               | add                 esp, 8
            //   84c0                 | test                al, al
            //   0f8490000000         | je                  0x96
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_7 = { 83c710 81c200010000 897d8c 895588 83ff40 0f8c42feffff 8b4df4 }
            // n = 7, score = 200
            //   83c710               | add                 edi, 0x10
            //   81c200010000         | add                 edx, 0x100
            //   897d8c               | mov                 dword ptr [ebp - 0x74], edi
            //   895588               | mov                 dword ptr [ebp - 0x78], edx
            //   83ff40               | cmp                 edi, 0x40
            //   0f8c42feffff         | jl                  0xfffffe48
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_8 = { 53 55 8b6f04 8bd1 2b2f d1ea 2bc2 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   8b6f04               | mov                 ebp, dword ptr [edi + 4]
            //   8bd1                 | mov                 edx, ecx
            //   2b2f                 | sub                 ebp, dword ptr [edi]
            //   d1ea                 | shr                 edx, 1
            //   2bc2                 | sub                 eax, edx

        $sequence_9 = { e9???????? 8d4d48 e9???????? 8d4d30 e9???????? 8d4dac e9???????? }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8d4d48               | lea                 ecx, [ebp + 0x48]
            //   e9????????           |                     
            //   8d4d30               | lea                 ecx, [ebp + 0x30]
            //   e9????????           |                     
            //   8d4dac               | lea                 ecx, [ebp - 0x54]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 2744320
}