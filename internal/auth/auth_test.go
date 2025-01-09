package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {

	type response struct {
		apiKey string
		err    error
	}

	cases := []struct {
		input    http.Header
		expected response
	}{
		{
			input: func() http.Header {
				h := http.Header{}
				h.Add("Authorization", "ApiKey VbJs7J+bhoCg9HOdpbvkiFTz7mE=")
				return h
			}(),
			expected: response{
				apiKey: "VbJs7J+bhoCg9HOdpbvkiFTz7mE=",
				err:    nil,
			},
		},
		{
			input: http.Header{},
			expected: response{
				apiKey: "",
				err:    ErrNoAuthHeaderIncluded,
			},
		},
		{
			input: func() http.Header {
				h := http.Header{}
				h.Add("Authorization", "VbJs7J+bhoCg9HOdpbvkiFTz7mE=")
				return h
			}(),
			expected: response{
				apiKey: "",
				err:    errors.New("malformed authorization header"),
			},
		},
	}

	for _, cs := range cases {
		apiKey, err := GetAPIKey(cs.input)
		if strings.Compare(apiKey, cs.expected.apiKey) != 0 {
			t.Errorf(
				`The actual and expected api keys are different
				Actual: %s
				Expected: %s`,
				apiKey,
				cs.expected.apiKey,
			)
		}

		if err != nil && err.Error() != cs.expected.err.Error() {
			t.Errorf(
				`The actual and expected errors are different
				Actual: %v
				Expected: %v`,
				err,
				cs.expected.err,
			)
		} else if err == nil && cs.expected.err != nil {
			t.Errorf("Expected error but got nil")
		}
	}
}
