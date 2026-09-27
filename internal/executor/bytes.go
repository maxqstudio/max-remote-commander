package executor

import (
	"bytes"
	"io"
)

func bytesReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}
