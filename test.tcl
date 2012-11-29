load ./tomcrypt.so
set k [string repeat "\x00" 32]
tomcrypt::cipherSetup symkey blowfish $k
set msg "Hello, World!   How are you?"
symkey ecbEncrypt msg
puts $msg
binary scan $msg H* hex
puts $hex
symkey ecbDecrypt msg
puts $msg
puts [symkey keySize 100]
symkey test
symkey done
