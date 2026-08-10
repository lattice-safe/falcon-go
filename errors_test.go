package falcon

import (
	"testing"
)

func TestErrorsStrings(t *testing.T) {
	errs := []error{
		ErrRandom,
		ErrSize,
		ErrFormat,
		ErrBadSignature,
		ErrBadArgument,
		ErrInternal,
	}
	for _, err := range errs {
		if err == nil || err.Error() == "" {
			t.Errorf("error %v had empty string", err)
		}
	}
}
