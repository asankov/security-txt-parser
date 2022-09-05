package security

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	CommentPrefix = "#"

	PolicyPrefix             = prefixed("Policy")
	HiringPrefix             = prefixed("Hiring")
	ContactPrefix            = prefixed("Contact")
	ExpiresPrefix            = prefixed("Expires")
	CanonicalPrefix          = prefixed("Canonical")
	EncryptionPrefix         = prefixed("Encryption")
	AcknowledgmentsPrefix    = prefixed("Acknowledgments")
	PreferredLanguagesPrefix = prefixed("Preferred-Languages")
)

func prefixed(s string) string {
	return s + ":"
}

var (
	ErrExpiresMustBePresentOnlyOnce            = fmt.Errorf("Expires field must be present only once")
	ErrPreferredLanguagesMustBePresentOnlyOnce = fmt.Errorf("PreferredLanguages field must be present only once")
	ErrContactMustBePresent                    = fmt.Errorf("Contact must be present")
	ErrExpiresMustBePresent                    = fmt.Errorf("Expires must be present")
	ErrExpiresNotAValidRFC3339Date             = fmt.Errorf("Expires is not a valid RFC3339 date")
)

var (
	defaultParser Parser

	// Parse parses a security.txt file using the default parser.
	Parse = defaultParser.Parse
)

// Parser is a struct that parses the security.txt file.
//
// Its purpose is to allow customization of the parsing via configuration.
// Currently no customizations are available.
type Parser struct{}

// Parse parses a security.txt file.
func (p *Parser) Parse(in io.Reader) (*TXT, error) {
	var (
		txt     TXT
		scanner = bufio.NewScanner(in)
	)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, CommentPrefix) || line == "" {
			continue
		}

		if strings.HasPrefix(line, AcknowledgmentsPrefix) {
			value := strings.TrimPrefix(line, AcknowledgmentsPrefix)
			value = strings.Trim(value, " ")

			txt.Acknowledgments = append(txt.Acknowledgments, value)
			continue
		}

		if strings.HasPrefix(line, CanonicalPrefix) {
			value := strings.TrimPrefix(line, CanonicalPrefix)
			value = strings.Trim(value, " ")

			txt.Canonical = append(txt.Canonical, value)
			continue
		}

		if strings.HasPrefix(line, ContactPrefix) {
			value := strings.TrimPrefix(line, ContactPrefix)
			value = strings.Trim(value, " ")

			txt.Contact = append(txt.Contact, value)
			continue
		}

		if strings.HasPrefix(line, EncryptionPrefix) {
			value := strings.TrimPrefix(line, EncryptionPrefix)
			value = strings.Trim(value, " ")

			txt.Encryption = value
			continue
		}

		if strings.HasPrefix(line, HiringPrefix) {
			value := strings.TrimPrefix(line, HiringPrefix)
			value = strings.Trim(value, " ")

			txt.Hiring = value
			continue
		}

		if strings.HasPrefix(line, ExpiresPrefix) {
			if !txt.Expires.IsZero() {
				return nil, ErrExpiresMustBePresentOnlyOnce
			}

			value := strings.TrimPrefix(line, ExpiresPrefix)
			value = strings.Trim(value, " ")

			expires, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, ErrExpiresNotAValidRFC3339Date
			}

			txt.Expires = expires
			continue
		}

		if strings.HasPrefix(line, PolicyPrefix) {
			value := strings.TrimPrefix(line, PolicyPrefix)
			value = strings.Trim(value, " ")

			txt.Policy = value
			continue
		}

		if strings.HasPrefix(line, PreferredLanguagesPrefix) {
			if len(txt.PreferredLanguages) != 0 {
				return nil, ErrPreferredLanguagesMustBePresentOnlyOnce
			}

			value := strings.TrimPrefix(line, PreferredLanguagesPrefix)
			value = strings.Trim(value, " ")

			values := strings.Split(value, ",")
			for _, value := range values {
				txt.PreferredLanguages = append(txt.PreferredLanguages, strings.Trim(value, " "))
			}
			continue
		}

		return nil, &UnknownSymbolError{Line: line}
	}

	if len(txt.Contact) == 0 {
		return nil, ErrContactMustBePresent
	}
	if txt.Expires.IsZero() {
		return nil, ErrExpiresMustBePresent
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &txt, nil
}
