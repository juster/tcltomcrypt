load ./tomcrypt.so
set k [string repeat "\x00" 32]
tomcrypt::cipherSetup key aes $k
set c [key ecbEncrypt "Hello, World!"]
binary scan $c H* hex
puts $hex
puts [key ecbDecrypt $c]
puts [key keySize 100]
key test
key done
