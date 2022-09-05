package security

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	commentPrefix = "#"

	policyPrefix             = prefixed("Policy")
	hiringPrefix             = prefixed("Hiring")
	contactPrefix            = prefixed("Contact")
	expiresPrefix            = prefixed("Expires")
	canonicalPrefix          = prefixed("Canonical")
	encryptionPrefix         = prefixed("Encryption")
	acknowledgmentsPrefix    = prefixed("Acknowledgments")
	preferredLanguagesPrefix = prefixed("Preferred-Languages")
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

		if strings.HasPrefix(line, commentPrefix) || line == "" {
			continue
		}

		if strings.HasPrefix(line, acknowledgmentsPrefix) {
			value := strings.TrimPrefix(line, acknowledgmentsPrefix)
			value = strings.Trim(value, " ")

			txt.Acknowledgments = append(txt.Acknowledgments, value)
			continue
		}

		if strings.HasPrefix(line, canonicalPrefix) {
			value := strings.TrimPrefix(line, canonicalPrefix)
			value = strings.Trim(value, " ")

			txt.Canonical = append(txt.Canonical, value)
			continue
		}

		if strings.HasPrefix(line, contactPrefix) {
			value := strings.TrimPrefix(line, contactPrefix)
			value = strings.Trim(value, " ")

			txt.Contact = append(txt.Contact, value)
			continue
		}

		if strings.HasPrefix(line, encryptionPrefix) {
			value := strings.TrimPrefix(line, encryptionPrefix)
			value = strings.Trim(value, " ")

			txt.Encryption = value
			continue
		}

		if strings.HasPrefix(line, hiringPrefix) {
			value := strings.TrimPrefix(line, hiringPrefix)
			value = strings.Trim(value, " ")

			txt.Hiring = value
			continue
		}

		if strings.HasPrefix(line, expiresPrefix) {
			if !txt.Expires.IsZero() {
				return nil, ErrExpiresMustBePresentOnlyOnce
			}

			value := strings.TrimPrefix(line, expiresPrefix)
			value = strings.Trim(value, " ")

			expires, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, ErrExpiresNotAValidRFC3339Date
			}

			txt.Expires = expires
			continue
		}

		if strings.HasPrefix(line, policyPrefix) {
			value := strings.TrimPrefix(line, policyPrefix)
			value = strings.Trim(value, " ")

			txt.Policy = value
			continue
		}

		if strings.HasPrefix(line, preferredLanguagesPrefix) {
			if len(txt.PreferredLanguages) != 0 {
				return nil, ErrPreferredLanguagesMustBePresentOnlyOnce
			}

			value := strings.TrimPrefix(line, preferredLanguagesPrefix)
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
