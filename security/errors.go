package security

import "fmt"

type UnknownSymbolError struct {
	Line string
}

func (e *UnknownSymbolError) Error() string {
	return "Unknown symbol: " + e.Line
}

type statusCodeError struct {
	statusCode int
	url        string
}

func (e *statusCodeError) Error() string {
	return fmt.Sprintf("Got non-200 response code - [%d] when calling [%s]", e.statusCode, e.url)
}
