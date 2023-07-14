//https://www.ptsecurity.com/ru-ru/research/pt-esc-threat-intelligence/apt-cloud-atlas-unbroken-threat/

rule PTESC_exploit_win_ZZ_MalDoc__CVE201711882__Rtf__CA
{
     strings:
         $equation = "4571756174696F6E" nocase ascii //180000004571756174696F6E
         $msftedit = "generator Msftedit 6.39.15" nocase ascii //generator Msftedit 6.39.15.1401
         $objclass = "objclass weaseoijsd" nocase ascii
     condition:
        uint32be ( 0 ) == 0x7B5C7274 and ($equation and ($msftedit or $objclass) or (for any i in (50..350) : (uint8be (@equation + i) == 0x64 and uint8be (@equation + i + 2) == 0x64 and uint8be (@equation + i + 4) == 0x64 and uint8be (@equation + i + 6) == 0x38)))
}

rule PTESC_tool_win_ZZ_OfficeTemplate__Downloader__DOC
{
	strings:
		$a = {00 A5 06 6E 04 B4}
		$b = {FF FF FF 7F FF FF FF 7F}
		$c = {B4 00 B4 00 81 81 12 30 00}
		$pref_1 = {68 00 74 00 74 00 70 00 3A 00 2F 00 2F}
		$pref_2 = {68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F}
	condition:
		uint16be ( 0 ) == 0xd0cf and ( for any i in ( 300 .. 400 ) : ( uint8be ( @a + i ) == 0x68 and uint8be ( @a + i + 2 ) == 0x74 and uint8be ( @a + i + 4 ) == 0x74 and uint8be ( @a + i + 6 ) == 0x70 ) or for any j in ( 100 .. 200 ) : ( uint8be ( @b + j ) == 0x68 and uint8be ( @b + j + 2 ) == 0x74 and uint8be ( @b + j + 4 ) == 0x74 and uint8be ( @b + j + 6 ) == 0x70 ) or for any k in ( 200 .. 400 ) : ( uint8be ( @c + k ) == 0x68 and uint8be ( @c + k + 2 ) == 0x74 and uint8be ( @c + k + 4 ) == 0x74 and uint8be ( @c + k + 6 ) == 0x70 ) ) and ( ( for any l in ( 14 .. 70 ) : ( uint8be ( @pref_1 + l ) == 0x2f ) ) or ( for any y in ( 16 .. 70 ) : ( uint8be ( @pref_2 + y ) == 0x2f ) ) )
}