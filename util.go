package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func removeMagic(data []byte) []byte {
	cut := data[5]
	data = data[8+2:]            // Removes token + two byte magic
	data = data[0 : len(data)-2] // Removes two byte magic at the end
	if len(data) < int(cut) {
		return data
	}
	data = data[cut:]
	return data
}

func getHeaderAndBody(data []byte) ([]byte, []byte) {
	cut := data[5]
	data = data[8+2:]            // Removes token + two byte magic
	data = data[0 : len(data)-2] // Removes two byte magic at the end
	if len(data) < int(cut) {
		return data, nil
	}
	header := data[:cut]
	data = data[cut:]
	return header, data
}

func removeHeaderForParse(data []byte) []byte {
	cut := data[6]
	data = removeMagic(data)
	if len(data) < int(cut) {
		return data
	}
	return data[cut:]
}

func xorDecrypt(data []byte, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

func reformData(data []byte) []byte {
	i := 0
	tokenSizeTotal := 0
	var messages [][]byte
	for i < len(data) {
		convId := data[i : i+4]
		remainingHeader := data[i+8 : i+28]
		contentLen := int(binary.LittleEndian.Uint32(data[i+24 : i+28]))
		content := data[i+28+4 : (i + 28 + 4 + contentLen)]

		formattedMessage := make([]byte, 24+contentLen)
		copy(formattedMessage, convId)
		copy(formattedMessage[4:], remainingHeader)
		copy(formattedMessage[24:], content)
		i += 28 + 4 + contentLen
		tokenSizeTotal += 4
		messages = append(messages, formattedMessage)
	}

	return bytes.Join(messages, []byte{})
}

func newKey(seed uint64) []byte {
	generator := MT19937_64_new()
	generator.Seed(seed)

	seed = generator.NextULong()
	generator.Seed(seed)

	_ = generator.NextULong() // Skip the first number.

	// Generate the key.
	btes := make([]byte, 0, 4096)
	for i := 0; i < 4096; i += 8 {
		btes = binary.BigEndian.AppendUint64(btes, generator.NextULong())
	}

	return btes
}

func guess(seed int64, serverSeed uint64, depth int, data []byte) (uint64, []byte) {
	generator := NewCSRand()
	generator.Seed(seed)
	for i := 0; i < depth; i++ {
		clientSeed := generator.Uint64()

		aSeed := clientSeed ^ serverSeed
		key := newKey(aSeed)

		clone := make([]byte, len(data))
		copy(clone, data)
		xorDecrypt(clone, key)
		if clone[0] == 0x45 && clone[1] == 0x67 && clone[len(data)-2] == 0x89 && clone[len(data)-1] == 0xAB {
			log.Println("Found encryption key seed:", aSeed, "at depth", i)
			return aSeed, key
		}
	}
	return 0, nil
}

func bruteforce(ms, serverSeed uint64, data []byte) (uint64, []byte) {
	for i := int64(0); i < 3000; i++ {
		offset := func() int64 {
			if i%2 == 0 {
				return i / 2
			}
			return -(i - 1) / 2
		}()
		time := int64(ms) + offset
		seed, key := guess(time, serverSeed, 5, data)
		if key != nil {
			log.Println("Found for time", time)
			return seed, key
		}
	}
	log.Println("Unable to find the encryption key seed.")
	return 0, nil
}

func decrypt(keypath string, ciphertext []byte) ([]byte, error) {
	rest, _ := os.ReadFile(keypath)
	// var ok bool
	var block *pem.Block
	var priv *rsa.PrivateKey
	for {
		block, rest = pem.Decode(rest)
		if block.Type == "RSA PRIVATE KEY" {
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				log.Println(err)
			} //else if priv, ok = k.(*rsa.PrivateKey); !ok {
			//	log.Println(fmt.Errorf("failed to parse private key"))
			//}
			priv = k
			break
		}
		if len(rest) == 0 {
			if priv == nil {
				log.Println(fmt.Errorf("failed to parse private key"))
			}
			break
		}
	}
	out := make([]byte, 0, 1024)
	for len(ciphertext) > 0 {
		chunkSize := 256
		if chunkSize > len(ciphertext) {
			chunkSize = len(ciphertext)
		}
		chunk := ciphertext[:chunkSize]
		ciphertext = ciphertext[chunkSize:]
		b, err := rsa.DecryptPKCS1v15(rand.Reader, priv, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
