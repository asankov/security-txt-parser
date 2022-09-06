package security

import (
	"time"
)

// TXT contains the information from the security.txt file.
type TXT struct {

	// Acknowledgments indicates a link to a page where security researchers are recognized for their reports.
	Acknowledgments []string

	// 	Canonical indicates the canonical URIs where the "security.txt" file is located.
	Canonical []string

	// Contact indicates an address that researchers should use for
	// reporting security vulnerabilities such as an email address, a phone
	// number and/or a web page with contact information.
	//
	// The "Contact" field MUST always be present in a "security.txt" file.
	// If this field indicates a web URI, then it MUST begin with "https://".
	// Security email addresses should use the conventions defined in section 4 of RFC2142.
	Contact []string

	// Encryption indicates an encryption key that security researchers should use for encrypted communication.
	Encryption string

	// Hiring is used for linking to the vendor's security-related job positions.
	Hiring string

	// Policy indicates a link to where the vulnerability disclosure policy is located.
	Policy string

	// Policy is used to indicate a set of natural languages that are preferred when submitting security reports.
	//
	// The values within this set are language tags as defined in RFC5646.
	//
	// If this field is absent, security researchers may assume that English is the language to be used as per section 4.5 of RFC2277.
	//
	// The order in which they appear is not an indication of priority; the
	// listed languages are intended to have equal priority.
	PreferredLanguages []string

	// Expires indicates the date and time after which the data contained in the "security.txt" file is considered stale and should not be used
	// The value of this field is formatted according to the Internet profile of ISO.8601 as defined in RFC3339.
	//
	// This field MUST always be present and MUST NOT appear more than once.
	Expires time.Time
}
