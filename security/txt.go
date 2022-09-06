package security

import (
	"time"
)

// TXT contains the information from the security.txt file.
type TXT struct {
	Acknowledgments []string
	Canonical       []string

	// Contact indicates an address that researchers should use for
	// reporting security vulnerabilities such as an email address, a phone
	// number and/or a web page with contact information.
	//
	// The "Contact" field MUST always be present in a "security.txt" file.
	// If this field indicates a web URI, then it MUST begin with "https://".
	// Security email addresses should use the conventions defined in section 4 of RFC2142.
	Contact []string

	// Encryption indicates an encryption key that security researchers should use for encrypted communication.
	Encryption         string
	Hiring             string
	Policy             string
	PreferredLanguages []string
	Expires            time.Time
}
