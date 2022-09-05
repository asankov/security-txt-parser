package security

import (
	"time"
)

// TXT contains the information from the security.txt file.
type TXT struct {
	Acknowledgments    []string
	Canonical          []string
	Contact            []string
	Encryption         string
	Hiring             string
	Policy             string
	PreferredLanguages []string
	Expires            time.Time
}
