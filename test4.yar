//https://yara.readthedocs.io/en/v4.1.3/modules/dotnet.html
import "dotnet"

rule not_exactly_five_streams
{
    condition:
        dotnet.number_of_streams != 5
}

rule blop_stream
{
    condition:
        for any i in (0..dotnet.number_of_streams - 1):
            (dotnet.streams[i].name == "#Blop")
}

rule exactly_five_streams_or_name_stream_or_version
{
    condition:
        for any i in (0..dotnet.number_of_streams - 1):
                    (dotnet.streams[i].name == "#~") or
                     dotnet.number_of_streams == 5 or
                     dotnet.version == "v4.0.30319"
}