package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectedError string
		shouldError   bool
	}{
		{
			name:          "Valid API key",
			authHeader:    "ApiKey abc123",
			expectedKey:   "abc123",
			expectedError: "",
			shouldError:   false,
		},
		{
			name:          "Valid API key with longer key",
			authHeader:    "ApiKey sk-1234567890abcdef",
			expectedKey:   "sk-1234567890abcdef",
			expectedError: "",
			shouldError:   false,
		},
		{
			name:          "No Authorization header",
			authHeader:    "",
			expectedKey:   "",
			expectedError: "no authorization header included",
			shouldError:   true,
		},
		{
			name:          "Only ApiKey without key",
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name:          "ApiKey with only space",
			authHeader:    "ApiKey ",
			expectedKey:   "",
			expectedError: "",
			shouldError:   false,
		},
		{
			name:          "Wrong prefix - Bearer instead of ApiKey",
			authHeader:    "Bearer abc123",
			expectedKey:   "",
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name:          "Wrong case - apikey instead of ApiKey",
			authHeader:    "apikey abc123",
			expectedKey:   "",
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name:          "Wrong case - APIKEY instead of ApiKey",
			authHeader:    "APIKEY abc123",
			expectedKey:   "",
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name:          "Multiple spaces between ApiKey and key",
			authHeader:    "ApiKey   abc123",
			expectedKey:   "",
			expectedError: "",
			shouldError:   false,
		},
		{
			name:          "ApiKey with key containing spaces",
			authHeader:    "ApiKey abc 123 def",
			expectedKey:   "abc",
			expectedError: "",
			shouldError:   false,
		},
		{
			name:          "Just random text",
			authHeader:    "random text here",
			expectedKey:   "",
			expectedError: "malformed authorization header",
			shouldError:   true,
		},
		{
			name:          "Empty string key after ApiKey",
			authHeader:    "ApiKey \"\"",
			expectedKey:   "\"\"",
			expectedError: "",
			shouldError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create headers
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			// Call the function
			key, err := GetAPIKey(headers)

			// Check error expectations
			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err.Error())
					return
				}
			}

			// Check key expectations (only if no error expected)
			if !tt.shouldError && key != tt.expectedKey {
				t.Errorf("Expected key '%s', got '%s'", tt.expectedKey, key)
			}
		})
	}
}

func TestGetAPIKey_SpecificErrorTypes(t *testing.T) {
	t.Run("No auth header returns ErrNoAuthHeaderIncluded", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)

		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("Empty auth header returns ErrNoAuthHeaderIncluded", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "")
		_, err := GetAPIKey(headers)

		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})
}
