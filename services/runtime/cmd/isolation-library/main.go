// Package main exposes the existing process_baseline implementation to the
// Python worker. It does not exec another process or install a weaker filter.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/isolation"
)

//export ApplyIsolation
func ApplyIsolation() *C.char {
	report, err := isolation.Apply()
	result := struct {
		Controls isolation.Report `json:"controls"`
		Error    string           `json:"error,omitempty"`
	}{Controls: report}
	if err != nil {
		result.Error = err.Error()
	}
	raw, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		return C.CString(`{"error":"isolation report failed"}`)
	}
	return C.CString(string(raw))
}

//export FreeIsolationReport
func FreeIsolationReport(ptr *C.char) { C.free(unsafe.Pointer(ptr)) }

func main() {}
