package detector

import (
	"net/http"
	"testing"
)

func TestBuildDetectionInput_Basic(t *testing.T) {
	input := buildDetectionInput("/api", "id=1", `{"name":"test"}`, http.Header{})
	if input.combined != `/apiid=1{"name":"test"}` {
		t.Errorf("combined mismatch: got %q", input.combined)
	}
	if input.cookieStr != "" {
		t.Errorf("cookieStr should be empty, got %q", input.cookieStr)
	}
	if input.decodedQuery == "" {
		t.Error("decodedQuery should not be empty")
	}
}

func TestBuildDetectionInput_WithCookies(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "session=abc")
	h.Add("Cookie", "user=xyz")
	h.Add("Set-Cookie", "lang=en")
	input := buildDetectionInput("/path", "", "", h)
	if input.cookieStr != "session=abc; user=xyz; lang=en; " {
		t.Errorf("cookieStr mismatch: got %q", input.cookieStr)
	}
	expected := "/path" + "session=abc; user=xyz; lang=en; "
	if input.combined != expected {
		t.Errorf("combined mismatch: got %q", input.combined)
	}
}

func TestBuildDetectionInput_NoCookies(t *testing.T) {
	input := buildDetectionInput("/", "q=1", "", http.Header{})
	if input.cookieStr != "" {
		t.Errorf("cookieStr should be empty, got %q", input.cookieStr)
	}
	if input.combined != "/q=1" {
		t.Errorf("combined mismatch: got %q", input.combined)
	}
}

func TestBuildDetectionInput_LowerCombined(t *testing.T) {
	input := buildDetectionInput("/API/Path", "", "", http.Header{})
	if input.lowerCombined != "/api/path" {
		t.Errorf("lowerCombined mismatch: got %q", input.lowerCombined)
	}
}

func TestBuildDetectionInput_DecodedQuery(t *testing.T) {
	input := buildDetectionInput("/", "name=hello%20world", "", http.Header{})
	if input.decodedQuery == "" {
		t.Error("decodedQuery should not be empty for percent-encoded query")
	}
}

func TestBuildDetectionInput_EmptyQuery(t *testing.T) {
	input := buildDetectionInput("/", "", "body", http.Header{})
	if input.decodedQuery != "" {
		t.Errorf("decodedQuery should be empty when query is empty, got %q", input.decodedQuery)
	}
}

func TestBuildDetectionInput_EmptyAll(t *testing.T) {
	input := buildDetectionInput("", "", "", http.Header{})
	if input.combined != "" {
		t.Errorf("combined should be empty, got %q", input.combined)
	}
	if input.lowerCombined != "" {
		t.Errorf("lowerCombined should be empty, got %q", input.lowerCombined)
	}
}

func TestBuildDetectionInput_OnlySetCookie(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "token=abc123")
	input := buildDetectionInput("/", "", "", h)
	if input.cookieStr != "token=abc123; " {
		t.Errorf("cookieStr mismatch: got %q", input.cookieStr)
	}
}
