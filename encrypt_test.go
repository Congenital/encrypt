package encrypt

import (
	"encoding/hex"
	mytime "git.sudoteam.com/gogroup/godin-account-system/utils/time"
	"git.sudoteam.com/gorepo/log"
	"testing"
	"time"
	"unsafe"
)

func TestEncode(t *testing.T) {
	aesTable := "02d042afed7f11e48c1d3417ebd98e50"

	ti := time.Now()
	ts := mytime.DecodeTime(&ti)
	log.Info(ts)
	data, err := EncryptData(aesTable, ts)
	if err != nil {
		log.Error(err)
		return
	}

	log.Info(data)
	log.Info(*(*[]byte)(unsafe.Pointer(&data)))

	d, err := Encrypt(aesTable, *(*[]byte)(unsafe.Pointer(&data)))
	if err != nil {
		log.Error(err)
		return
	}

	log.Info(hex.EncodeToString(d))

	d, err = Decrypt(aesTable, d)
	if err != nil {
		log.Error(err)
		return
	}

	log.Info(aesTable, ti)

	uuid, u_time, err := DecryptData(*(*string)(unsafe.Pointer(&d)))
	if err != nil {
		log.Error(err)
		return
	}
	log.Info(u_time)

	m_time, err := mytime.EncodeTime(u_time)
	log.Info(uuid, m_time, err)
}
