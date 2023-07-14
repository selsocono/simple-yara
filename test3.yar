rule Golang_binaries
{
	strings:
		$str1 = "fatal error: cgo callback before cgo call"
		$str2 = "golang.org"
		$str3 = "Go buildinf:"
		$str4 = "go.buildid"
		$str5 = "Go build ID:"
	condition:
		( uint16be ( 0 ) == 0x7F45 or uint16be ( 0 ) == 0x4D5A ) and ( any of ( $str* ) )
}