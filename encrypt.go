package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"git.sudoteam.com/gogroup/godin-account-system/utils/time"
	"git.sudoteam.com/gorepo/log"
	"io"
	"strconv"
	"unsafe"
)

// AES加密
func Encrypt(aesTable string, src []byte) ([]byte, error) {
	// 验证输入参数
	// 必须为aes.Blocksize的倍数
	defer func() {
		if err := recover(); err != nil {
			log.Error(err)
		}
	}()

	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}

	block, err := aes.NewCipher(*(*[]byte)(unsafe.Pointer(&aesTable)))
	if err != nil {
		return nil, err
	}

	src = PKCS5Padding(src, aes.BlockSize)
	encryptText := make([]byte, aes.BlockSize+len(src))

	iv := encryptText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptText[aes.BlockSize:], src)

	return encryptText, nil
}

// AES解密
func Decrypt(aesTable string, src []byte) ([]byte, error) {
	// hex
	decryptText, err := hex.DecodeString(fmt.Sprintf("%x", string(src)))
	if err != nil {
		return nil, err
	}

	// 长度不能小于aes.Blocksize
	if len(decryptText) < aes.BlockSize {
		return nil, errors.New("crypto/cipher: ciphertext too short")
	}

	iv := decryptText[:aes.BlockSize]
	decryptText = decryptText[aes.BlockSize:]

	// 验证输入参数
	// 必须为aes.Blocksize的倍数
	if len(decryptText)%aes.BlockSize != 0 {
		return nil, errors.New("crypto/cipher: ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher([]byte(aesTable))
	if err != nil {
		panic("aes.NewCipher: " + err.Error())
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(decryptText, decryptText)

	decryptText = PKCS5UnPadding(decryptText)

	return decryptText, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func EncryptData(data string, ts *time.TS) (string, error) {

	if len(data) < 32 {
		return "", errors.New("data length error")
	}

	str := "0" + data[0:2] + "0" + data[2:4] + ts.Year1 + data[4:6] + ts.Year2 + data[6:8] +
		ts.Year3 + data[8:10] + ts.Year4 + data[10:12] + ts.Bmouth + data[12:14] +
		ts.Amouth + data[14:16] + ts.Bday + data[16:18] + ts.Aday + data[18:20] +
		ts.Bhour + data[20:22] + ts.Ahour + data[22:24] + ts.Bminute + data[24:26] +
		ts.Aminute + data[26:28] + ts.Bsecond + data[28:30] + ts.Asecond + data[30:32]

	return str, nil
}

func DecryptData(data string) (string, *time.TS, error) {
	var d []byte
	d = append(d, data[1], data[2], data[4], data[5], data[7], data[8],
		data[10], data[11], data[13], data[14], data[16], data[17],
		data[19], data[20], data[22], data[23], data[25], data[26],
		data[28], data[29], data[31], data[32], data[34], data[35],
		data[37], data[38], data[40], data[41], data[43], data[44],
		data[46], data[47])

	t := &time.TS{}
	t.Year1 = strconv.Itoa(int(data[6] - 48))
	t.Year2 = strconv.Itoa(int(data[9] - 48))
	t.Year3 = strconv.Itoa(int(data[12] - 48))
	t.Year4 = strconv.Itoa(int(data[15] - 48))
	t.Bmouth = strconv.Itoa(int(data[18] - 48))
	t.Amouth = strconv.Itoa(int(data[21] - 48))
	t.Bday = strconv.Itoa(int(data[24] - 48))
	t.Aday = strconv.Itoa(int(data[27] - 48))
	t.Bhour = strconv.Itoa(int(data[30] - 48))
	t.Ahour = strconv.Itoa(int(data[33] - 48))
	t.Bminute = strconv.Itoa(int(data[36] - 48))
	t.Aminute = strconv.Itoa(int(data[39] - 48))
	t.Bsecond = strconv.Itoa(int(data[42] - 48))
	t.Asecond = strconv.Itoa(int(data[45] - 48))

	return string(d), t, nil
}
