load ./tomcrypt.so

array set blowfish $tomcrypt::cipher(blowfish)
puts "block length: $blowfish(block_length)"

set k [string repeat "\x00" 32]
set sym [tomcrypt::blowfish_setup $k]
exit
$sym ecb_encrypt 
puts $sym
exit 0

tomcrypt::cipher symkey blowfish $k
set msg "Hello, World!"
symkey ecbEncrypt msg
puts $msg
binary scan $msg H* hex
puts $hex
symkey ecbDecrypt msg
puts $msg
puts [symkey keySize 100]
symkey test
symkey done
