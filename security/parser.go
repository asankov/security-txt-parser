package security

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
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
	// ErrExpiresMustBePresentOnlyOnce is returned when the Expires field is present more than once.
	ErrExpiresMustBePresentOnlyOnce = fmt.Errorf("Expires field must be present only once") //nolint:stylecheck
	// ErrPreferredLanguagesMustBePresentOnlyOnce is returned when the PreferredLanguages field is present more than once.
	ErrPreferredLanguagesMustBePresentOnlyOnce = fmt.Errorf("PreferredLanguages field must be present only once")
	// ErrContactMustBePresent is returned when the Contact field is not present.
	ErrContactMustBePresent = fmt.Errorf("Contact must be present") //nolint:stylecheck
	// ErrExpiresMustBePresent is returned when the Expires field is not present.
	ErrExpiresMustBePresent = fmt.Errorf("Expires must be present") //nolint:stylecheck
	// ErrExpiresNotAValidRFC3339Date is returned when the Expires field is not a valid RFC3339 date.
	ErrExpiresNotAValidRFC3339Date = fmt.Errorf("Expires is not a valid RFC3339 date") //nolint:stylecheck
)

var (
	defaultParser Parser = *NewParserWithOptions(ParserOptions{
		Logger: slog.Default(),
	})

	// Parse parses a security.txt file using the default parser.
	Parse = defaultParser.Parse

	ParseFromURL = defaultParser.ParseFromURL
)

// Parser is a struct that parses the security.txt file.
//
// Its purpose is to allow customization of the parsing via configuration.
type Parser struct {
	logger     *slog.Logger
	httpClient *http.Client
}

type ParserOptions struct {
	Logger     *slog.Logger
	HTTPClient *http.Client
}

func NewParser() *Parser {
	return NewParserWithOptions(ParserOptions{
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		HTTPClient: http.DefaultClient,
	})
}

func NewParserWithOptions(opts ParserOptions) *Parser {
	p := &Parser{}
	if opts.Logger != nil {
		p.logger = opts.Logger
	}
	if opts.HTTPClient != nil {
		p.httpClient = opts.HTTPClient
	}
	return p
}

func (p *Parser) SetLogger(logger *slog.Logger) *Parser {
	p.logger = logger
	return p
}

// Parse parses a security.txt file.
//
//nolint:funlen,gocognit,cyclop
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
		return nil, fmt.Errorf("error while reading file: %w", err)
	}

	return &txt, nil
}

func (p *Parser) ParseFromURL(rawURL string) (*TXT, error) {

	url, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse provided URL [%s]: %w", rawURL, err)
	}

	res, err := p.parseFromURL(rawURL)

	if err == nil {
		return res, nil
	}

	var multiErr *multierror.Error
	multiErr = multierror.Append(multiErr, err)

	p.logger.Warn("Unable to parse file at given location", "url", rawURL, "error", err)

	if url.Path == "/" || url.Path == "" {
		p.logger.Warn("Provided URL has empty path, trying more URLs with known paths", "url", url)

		trimmedURL := strings.TrimSuffix(url.String(), "/")
		for _, path := range []string{"security.txt", ".well-known/security.txt"} {
			newURL := trimmedURL + "/" + path

			p.logger.Info("Trying URL", "url", newURL)

			res, err := p.parseFromURL(newURL)

			if err == nil {
				return res, nil
			} else {
				p.logger.Warn("Unable to parse file at given location", "url", newURL, "error", err)

				multiErr = multierror.Append(multiErr, err)
			}
		}
	}

	return nil, multiErr.ErrorOrNil()
}

func (p *Parser) parseFromURL(url string) (*TXT, error) {
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {
		return nil, &statusCodeError{
			statusCode: resp.StatusCode,
			url:        url,
		}
	}

	return p.Parse(resp.Body)
}
