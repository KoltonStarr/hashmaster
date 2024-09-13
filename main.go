package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
)


func main() {
	// Survey for input
    hashAlgorithms := []string{
		"MD5", 
		"SHA-256", 
		"SHA-512",
		"BLAKE2b", 
		"BLAKE2s", 
		"HMAC",
	}

	color.HiBlue("********** Welcome to the Hash Master! **********")

    algorithmPrompt := &survey.Select{
		Message: "Choose a hashing algorithm:",
        Options: hashAlgorithms,
    }
	
	var selectedOption string
    err := survey.AskOne(algorithmPrompt, &selectedOption)

    if err != nil {
        fmt.Println("Error:", err)
        return
    }

	messagePrompt := &survey.Input{
		Message: "Enter the text to hash:",
	}

	var message string
	survey.AskOne(messagePrompt, &message)

	var hasher hash.Hash

    switch selectedOption {
	case "MD5":
		hasher = md5.New()
    case "SHA-256":
        hasher = sha256.New()
    case "SHA-512":
        hasher = sha512.New()
    case "BLAKE2b":
        hasher, err = blake2b.New256(nil)
        if err != nil {
            fmt.Println("Error:", err)
            return
        }
    case "BLAKE2s":
        hasher, err = blake2s.New256(nil)
        if err != nil {
            fmt.Println("Error:", err)
            return
        }
    case "HMAC":
        hasher = hmac.New(sha256.New, []byte("secret"))
    default:
        fmt.Println("Unknown algorithm selected")
        return
    }

    hasher.Write([]byte(message))
    hash := hasher.Sum(nil)
	color.White("Hash: %x\n", hash)

	
}