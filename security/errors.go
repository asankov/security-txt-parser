package security

type UnknownSymbolError struct {
	Line string
}

func (e *UnknownSymbolError) Error() string {
	return "Unknown symbol: " + e.Line
}
