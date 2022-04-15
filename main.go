package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
)

func main() {

	var file1 string = "D:/matang.png"
	var file2 string = "D:/matang2.png"
	var file3 string = "D:/matang3.png"
	var file_kunci string = "D:/key.txt"

	plaintext, _ := ioutil.ReadFile(file1)

	key, _ := ioutil.ReadFile(file_kunci)

	//lakukan enkripsi
	byte_enkrip := encrypt(plaintext, key)
	ioutil.WriteFile(file2, byte_enkrip, 777)

	//lakukan dekripsi
	byte_dekrip, _ := ioutil.ReadFile(file2)
	var byte_dekrip2 []byte = decrypt(byte_dekrip, key)
	ioutil.WriteFile(file3, byte_dekrip2, 777)

}

func encrypt(plainstring, keystring []byte) []byte {
	// Byte array of the string
	plaintext := plainstring //[]byte(plainstring)

	// Key
	key := keystring //[]byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Empty array of 16 + plaintext length
	// Include the IV at the beginning
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// Slice of first 16 bytes
	iv := ciphertext[:aes.BlockSize]

	// Write 16 rand bytes to fill iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Return an encrypted stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt bytes from plaintext to ciphertext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func decrypt(cipherstring, keystring []byte) []byte {
	// Byte array of the string
	ciphertext := cipherstring //[]byte(cipherstring)

	// Key
	key := keystring //[]byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Before even testing the decryption,
	// if the text is too small, then it is incorrect
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}

	// Get the 16 byte IV
	iv := ciphertext[:aes.BlockSize]

	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]

	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	return (ciphertext)
}
