lappend auto_path .
package require tomcrypt

array set blowfish $tomcrypt::cipher(blowfish)
puts "block length: $blowfish(block_length)"

proc hexdump {str} {
    binary scan $str H* hex
    puts $hex
}

set k [string repeat "\x00" 32]
set sym [tomcrypt::blowfish_setup $k]
set pt "Hello!\x00\x00"
puts $pt
hexdump $pt
set ct [tomcrypt::blowfish_ecb_encrypt $pt $sym]
puts "<cipher text>"
hexdump $ct
set pt [tomcrypt::blowfish_ecb_decrypt $ct $sym]
puts $pt
hexdump $pt

puts "sym = $sym"
tomcrypt::aes_ecb_encrypt [string repeat "\x00" 16] $sym

tomcrypt::blowfish_done $sym

namespace delete tomcrypt

