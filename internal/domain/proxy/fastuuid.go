package proxy

import (
	crypto_rand "crypto/rand"
	"sync"
)

var uuidPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 16)
		return &b
	},
}

func fastUUID() string {
	bp, ok := uuidPool.Get().(*[]byte)
	if !ok || bp == nil {
		b := make([]byte, 16)
		bp = &b
	}
	b := *bp
	if _, err := crypto_rand.Read(b); err != nil {
		uuidPool.Put(bp)
		panic("crypto/rand.Read failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var buf [36]byte
	hexEncode(buf[:], b)
	uuidPool.Put(bp)
	return string(buf[:])
}

const hexTable = "0123456789abcdef"

func hexEncode(dst []byte, src []byte) {
	dst[0] = hexTable[src[0]>>4]
	dst[1] = hexTable[src[0]&0x0f]
	dst[2] = hexTable[src[1]>>4]
	dst[3] = hexTable[src[1]&0x0f]
	dst[4] = '-'
	dst[5] = hexTable[src[2]>>4]
	dst[6] = hexTable[src[2]&0x0f]
	dst[7] = hexTable[src[3]>>4]
	dst[8] = hexTable[src[3]&0x0f]
	dst[9] = '-'
	dst[10] = hexTable[src[4]>>4]
	dst[11] = hexTable[src[4]&0x0f]
	dst[12] = hexTable[src[5]>>4]
	dst[13] = hexTable[src[5]&0x0f]
	dst[14] = '-'
	dst[15] = hexTable[src[6]>>4]
	dst[16] = hexTable[src[6]&0x0f]
	dst[17] = hexTable[src[7]>>4]
	dst[18] = hexTable[src[7]&0x0f]
	dst[19] = '-'
	dst[20] = hexTable[src[8]>>4]
	dst[21] = hexTable[src[8]&0x0f]
	dst[22] = hexTable[src[9]>>4]
	dst[23] = hexTable[src[9]&0x0f]
	dst[24] = hexTable[src[10]>>4]
	dst[25] = hexTable[src[10]&0x0f]
	dst[26] = hexTable[src[11]>>4]
	dst[27] = hexTable[src[11]&0x0f]
	dst[28] = hexTable[src[12]>>4]
	dst[29] = hexTable[src[12]&0x0f]
	dst[30] = hexTable[src[13]>>4]
	dst[31] = hexTable[src[13]&0x0f]
	dst[32] = hexTable[src[14]>>4]
	dst[33] = hexTable[src[14]&0x0f]
	dst[34] = hexTable[src[15]>>4]
	dst[35] = hexTable[src[15]&0x0f]
}
