load ./tomcrypt.so

array set aes $tomcrypt::cipher(aes)
puts "block length: $aes(block_length)"

set k [string repeat "\x00" 32]
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
