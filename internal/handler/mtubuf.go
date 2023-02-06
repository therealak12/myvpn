package handler

import (
	"sync"

	"github.com/therealak12/myvpn/internal/consts"
)

var (
	bufPool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, consts.MTU)
		},
	}
)

func newBuffer() []byte {
	return bufPool.Get().([]byte)
}

func releaseBuffer(buf []byte) {
	bufPool.Put(buf)
}
