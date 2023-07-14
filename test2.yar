import "pe"

rule signed
{
    condition:
          pe.is_signed
}