package randomstring

import "testing"

func TestGen(t *testing.T) {
	t.Log(Gen(32))
}

func TestGenReadable(t *testing.T) {
	t.Log(GenReadable(32))
}
