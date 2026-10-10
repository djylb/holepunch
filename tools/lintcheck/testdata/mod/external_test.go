package mod_test

import (
	"testing"

	"example.com/mod"
)

func TestExported(t *testing.T) { mod.Exported = 2 }
