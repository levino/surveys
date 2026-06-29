package ui

import (
	"strconv"

	"github.com/a-h/templ"
)

var Theme = "surveys"

func itoa(i int) string { return strconv.Itoa(i) }

func optAttrs(f FormField) templ.Attributes {
	a := templ.Attributes{}
	if f.MaxLength > 0 {
		a["maxlength"] = strconv.Itoa(f.MaxLength)
	}
	return a
}
