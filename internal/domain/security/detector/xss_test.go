package detector

import "testing"

func TestXSSDetector_Detect(t *testing.T) {
	d := NewXSSDetector()

	positives := []string{
		"<script>alert(1)</script>",
		"<script>document.cookie</script>",
		"<img src=x onerror=alert(1)>",
		"<body onload=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		"<img src=javascript:alert(1)>",
		"<a href=javascript:alert(1)>click</a>",
		"<div onmouseover=alert(1)>hover</div>",
		"<input onfocus=alert(1) autofocus>",
		"<iframe src=javascript:alert(1)>",
		"<object data=javascript:alert(1)>",
		"<embed src=javascript:alert(1)>",
	}

	for i, payload := range positives {
		detected, _, _, _ := d.Detect(payload)
		if !detected {
			t.Errorf("positive case %d should be detected: %q", i, payload)
		}
	}
}

func TestXSSDetector_Negatives(t *testing.T) {
	d := NewXSSDetector()

	negatives := []string{
		"hello world",
		"<p>normal paragraph</p>",
		"<div>content</div>",
		"<span>text</span>",
	}

	for i, payload := range negatives {
		detected, _, _, _ := d.Detect(payload)
		if detected {
			t.Errorf("negative case %d should NOT be detected: %q", i, payload)
		}
	}
}

func TestXSSDetector_DetectRequest(t *testing.T) {
	d := NewXSSDetector()

	detected, _, loc, _, _ := d.DetectRequest("GET", "/api/search?q=<script>alert(1)</script>", "", "", nil)
	if !detected {
		t.Error("XSS in path should be detected")
	}
	if loc != "path" {
		t.Errorf("expected location 'path', got %q", loc)
	}

	detected, _, loc, _, _ = d.DetectRequest("GET", "/api/search", "q=<img src=x onerror=alert(1)>", "", nil)
	if !detected {
		t.Error("XSS in query should be detected")
	}
	if loc != "query" {
		t.Errorf("expected location 'query', got %q", loc)
	}

	detected, _, loc, _, _ = d.DetectRequest("POST", "/api/comment", "", "comment=<script>alert(1)</script>", nil)
	if !detected {
		t.Error("XSS in POST body should be detected")
	}
	if loc != "body" {
		t.Errorf("expected location 'body', got %q", loc)
	}
}

func TestXSSDetector_GetPatternCount(t *testing.T) {
	d := NewXSSDetector()
	count := d.GetPatternCount()
	if count == 0 {
		t.Error("XSS detector should have patterns")
	}
}
