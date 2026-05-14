package detector

import (
	"net/http"
	"net/url"
	"strings"
)

type detectionInput struct {
	combined      string
	lowerCombined string
	cookieStr     string
	decodedQuery  string
}

func buildDetectionInput(path, query, body string, headers http.Header) detectionInput {
	var input detectionInput

	cookieValues := headers.Values("Cookie")
	setCookieValues := headers.Values("Set-Cookie")
	if len(cookieValues) > 0 || len(setCookieValues) > 0 {
		var csb strings.Builder
		totalCookieLen := 0
		for _, c := range cookieValues {
			totalCookieLen += len(c) + 2
		}
		for _, c := range setCookieValues {
			totalCookieLen += len(c) + 2
		}
		csb.Grow(totalCookieLen)
		for _, c := range cookieValues {
			csb.WriteString(c)
			csb.WriteString("; ")
		}
		for _, c := range setCookieValues {
			csb.WriteString(c)
			csb.WriteString("; ")
		}
		input.cookieStr = csb.String()
	}

	totalLen := len(path) + len(query) + len(body) + len(input.cookieStr)
	var sb strings.Builder
	sb.Grow(totalLen)
	sb.WriteString(path)
	if query != "" {
		sb.WriteString(query)
	}
	if body != "" {
		sb.WriteString(body)
	}
	if input.cookieStr != "" {
		sb.WriteString(input.cookieStr)
	}
	input.combined = sb.String()

	input.lowerCombined = strings.ToLower(input.combined)

	if query != "" {
		if values, err := url.ParseQuery(query); err == nil && len(values) > 0 {
			var dsb strings.Builder
			dsb.Grow(len(query))
			for key, vals := range values {
				for _, value := range vals {
					dsb.WriteString(key)
					dsb.WriteString("=")
					dsb.WriteString(value)
					dsb.WriteString("&")
				}
			}
			input.decodedQuery = dsb.String()
		}
	}

	return input
}
