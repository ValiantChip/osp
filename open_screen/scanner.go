package open_screen

import (
	"errors"
	"io"

	vint "github.com/CzarJoti/osp/variable_int"
	cbor "github.com/fxamacker/cbor/v2"
)

const (
	maxBufferSize     = 16384
	defaultBufferSize = 1024
)

// implements a scanner for cbor data
type Scanner struct {
	key   TypeKey
	data  any
	r     io.Reader
	buf   []byte
	start int
	end   int
	atEOF bool
	err   error
	done  bool
}

var (
	ErrNegativeAdvance = errors.New("open_screen.Scanner: SplitFunc returns negative advance count")
	ErrAdvanceTooFar   = errors.New("open_screen.Scanner: SplitFunc returns advance count beyond input")
	ErrBufFull         = errors.New("open_screen.Scanner: buffer is full")
)

func NewScanner(r io.Reader) *Scanner {
	return &Scanner{
		r:   r,
		buf: make([]byte, defaultBufferSize),
		err: nil,
	}
}

func (s *Scanner) setErr(err error) {
	if s.err == nil {
		s.err = err
	}
}

func (s *Scanner) Advance(n int) bool {
	if n < 0 {
		s.setErr(ErrNegativeAdvance)
		return false
	}
	if s.start+n > s.end {
		s.setErr(ErrAdvanceTooFar)
		return false
	}
	s.start += n
	return true
}

func (s *Scanner) Scan() bool {
	if s.done {
		return false
	}

	for {
		advance, key, data, err := cborDecode(s.buf[s.start:s.end])
		if !s.Advance(advance) {
			return false
		}
		if err == nil {
			s.key = key
			s.data = data
			return true
		}

		if errors.As(err, new(*cbor.InvalidUnmarshalError)) {
			s.setErr(err)
			return false
		}

		if s.atEOF || s.err != nil {
			return false
		}

		if s.end == len(s.buf) {
			if s.start > 0 {
				copy(s.buf, s.buf[s.start:s.end])
				s.end -= s.start
				s.start = 0
			} else {
				newsize := min(len(s.buf)*2, maxBufferSize)
				if newsize == len(s.buf) {
					s.setErr(ErrBufFull)
					return false
				}

				newbuf := make([]byte, newsize)
				copy(newbuf, s.buf[:s.end])
				s.buf = newbuf
			}
		}

		n, err := s.r.Read(s.buf[s.end:len(s.buf)])
		s.end += n
		if err != nil {
			if err == io.EOF {
				s.atEOF = true
			} else {
				s.setErr(err)
				return false
			}
		}
	}
}

func (s *Scanner) GetVal() (TypeKey, any) {
	return s.key, s.data
}

func (s *Scanner) Err() error {
	return s.err
}

func cborDecode(data []byte) (int, TypeKey, any, error) {
	length := vint.GetLength(data[0])
	var key TypeKey = vint.GetValue(data, length)
	v := GetVal(key)
	rest, err := cbor.UnmarshalFirst(data[length:], v)
	if err == nil {
		advance := len(data) - len(rest)
		return advance, key, v, nil
	}

	return 0, 0, nil, err
}
