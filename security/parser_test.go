package security_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/asankov/security-txt-parser/security"
	"github.com/stretchr/testify/require"
)

func TestSecurity(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		loadFn func(t *testing.T) (*security.TXT, error)
	}{
		{
			name: "load from file",
			loadFn: func(t *testing.T) (*security.TXT, error) {
				file, err := os.Open("testdata/security.txt")
				require.NoError(t, err)

				t.Cleanup(func() {
					file.Close()
				})

				return security.Parse(file)
			},
		},
		{
			name: "load from URL - /",
			loadFn: func(t *testing.T) (*security.TXT, error) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "" && r.URL.Path != "/" {
						t.Fatalf("Got unexpected path - %s", r.URL.Path)
						return
					}

					file, err := os.Open("testdata/security.txt")
					require.NoError(t, err)

					t.Cleanup(func() {
						file.Close()
					})

					bytes, err := io.ReadAll(file)
					require.NoError(t, err)

					_, err = w.Write(bytes)
					require.NoError(t, err)
				}))
				t.Cleanup(srv.Close)

				return security.ParseFromURL(srv.URL)
			},
		},
		{
			name: "load from URL - /security.txt",
			loadFn: func(t *testing.T) (*security.TXT, error) {
				srv := serverFor(t, "/security.txt")

				t.Cleanup(srv.Close)

				return security.ParseFromURL(srv.URL)
			},
		},
		{
			name: "load from URL - /.well-known/security.txt",
			loadFn: func(t *testing.T) (*security.TXT, error) {
				srv := serverFor(t, "/.well-known/security.txt")

				t.Cleanup(srv.Close)

				return security.ParseFromURL(srv.URL)
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			txt, err := testCase.loadFn(t)
			require.NoError(t, err)

			require.NotNil(t, txt)

			require.Equal(t, 1, len(txt.Acknowledgments))
			require.Equal(t, "https://example.com/", txt.Acknowledgments[0])

			require.Equal(t, 2, len(txt.Canonical))
			require.Contains(t, txt.Canonical, "https://www.example.com/.well-known/security.txt")
			require.Contains(t, txt.Canonical, "https://someserver.example.com/.well-known/security.txt")

			require.Equal(t, 2, len(txt.Contact))
			require.Contains(t, txt.Contact, "https://example.com/vulnz")
			require.Contains(t, txt.Contact, "mailto:security@example.com")

			require.NotEmpty(t, txt.Encryption)
			require.Equal(t, "https://example.com/publickey.txt", txt.Encryption)

			require.False(t, txt.Expires.IsZero())
			year, month, day := txt.Expires.Date()
			require.Equal(t, 2021, year)
			require.Equal(t, time.December, month)
			require.Equal(t, 31, day)

			require.NotEmpty(t, txt.Policy)
			require.Equal(t, "https://example.com/policy", txt.Policy)

			require.NotEmpty(t, txt.Hiring)
			require.Equal(t, "https://example.com/hiring", txt.Hiring)

			require.Equal(t, 3, len(txt.PreferredLanguages))
			require.Contains(t, txt.PreferredLanguages, "en")
			require.Contains(t, txt.PreferredLanguages, "es")
			require.Contains(t, txt.PreferredLanguages, "fr")
		})
	}
}

func serverFor(t *testing.T, path string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		file, err := os.Open("testdata/security.txt")
		require.NoError(t, err)

		t.Cleanup(func() {
			file.Close()
		})

		bytes, err := io.ReadAll(file)
		require.NoError(t, err)

		_, err = w.Write(bytes)
		require.NoError(t, err)
	}))
}

func ExampleParse() {
	file, err := os.Open("testdata/security.txt")
	if err != nil {
		// error handling
		return
	}

	defer file.Close()

	txt, err := security.Parse(file)
	if err != nil {
		// error handling
		return
	}

	fmt.Println(txt.Contact[0])
	fmt.Println(txt.Contact[1])
	// Output:
	// https://example.com/vulnz
	// mailto:security@example.com
}

func TestSecurityErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		fileName      string
		expectedError error
	}{
		{
			name:          "Preferred-Languages present more than once",
			fileName:      "security-2-pref-lang.txt",
			expectedError: security.ErrPreferredLanguagesMustBePresentOnlyOnce,
		},
		{
			name:          "Expires present more than once",
			fileName:      "security-2-expires.txt",
			expectedError: security.ErrExpiresMustBePresentOnlyOnce,
		},
		{
			name:          "Contact must be present",
			fileName:      "security-no-contact.txt",
			expectedError: security.ErrContactMustBePresent,
		},
		{
			name:          "Expires must be present",
			fileName:      "security-no-expires.txt",
			expectedError: security.ErrExpiresMustBePresent,
		},
		{
			name:          "Expires not a valid date",
			fileName:      "security-not-valid-date.txt",
			expectedError: security.ErrExpiresNotAValidRFC3339Date,
		},
		{
			name:          "File contains unknown symbol",
			fileName:      "security-unknown-symbol.txt",
			expectedError: &security.UnknownSymbolError{Line: "SHOULD FAIL HERE."},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			file, err := os.Open("testdata/" + testCase.fileName)
			require.NoError(t, err)

			t.Cleanup(func() {
				file.Close()
			})

			txt, err := security.Parse(file)
			require.Nil(t, txt)
			require.Error(t, err)
			require.Equal(t, testCase.expectedError, err)
		})
	}
}

func TestParseFromURLNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, err := security.ParseFromURL(srv.URL)
	require.Error(t, err)
}
