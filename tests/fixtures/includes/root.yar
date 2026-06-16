include "common.yar"

rule encoded_powershell {
    strings:
        $enc = "-enc" ascii
    condition:
        powershell_process and $enc
}
