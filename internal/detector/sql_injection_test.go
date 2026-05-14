package detector

import "testing"

func TestSQLInjectionDetector_Detect(t *testing.T) {
	d := NewSQLInjectionDetector()

	positives := []string{
		"1' OR '1'='1",
		"' OR 1=1--",
		"1 UNION SELECT username,password FROM users--",
		"1 UNION ALL SELECT 1,2,3--",
		"admin'--",
		"SELECT * FROM users",
		"' OR SLEEP(5)--",
		"1; DROP TABLE users--",
		"1' AND 1=1--",
		"/*!union*/ /*!select*/ 1,2,3",
		"1; INSERT INTO users VALUES('hack')--",
		"1; UPDATE users SET password='hack'--",
		"1; DELETE FROM users--",
		"(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables)",
		"' waitfor delay '0:0:10'--",
	}

	for i, payload := range positives {
		detected, _, _, _ := d.Detect(payload)
		if !detected {
			t.Errorf("positive case %d should be detected: %q", i, payload)
		}
	}
}

func TestSQLInjectionDetector_Negatives(t *testing.T) {
	d := NewSQLInjectionDetector()

	negatives := []string{
		"hello world",
		"normal text content",
		"12345",
		"test@example.com",
	}

	for i, payload := range negatives {
		detected, _, _, _ := d.Detect(payload)
		if detected {
			t.Errorf("negative case %d should NOT be detected: %q", i, payload)
		}
	}
}

func TestSQLInjectionDetector_DetectRequest(t *testing.T) {
	d := NewSQLInjectionDetector()

	detected, _, loc, _, _ := d.DetectRequest("GET", "/api/user?id=1' OR 1=1--", "", "", nil)
	if !detected {
		t.Error("SQLi in path should be detected")
	}
	if loc != "path" {
		t.Errorf("expected location 'path', got %q", loc)
	}

	detected, _, loc, _, _ = d.DetectRequest("GET", "/api/user", "id=1' OR 1=1--", "", nil)
	if !detected {
		t.Error("SQLi in query should be detected")
	}
	if loc != "query" {
		t.Errorf("expected location 'query', got %q", loc)
	}

	detected, _, loc, _, _ = d.DetectRequest("POST", "/api/login", "", "username=admin' OR '1'='1", nil)
	if !detected {
		t.Error("SQLi in POST body should be detected")
	}
	if loc != "body" {
		t.Errorf("expected location 'body', got %q", loc)
	}
}

func TestSQLInjectionDetector_GetPatternCount(t *testing.T) {
	d := NewSQLInjectionDetector()
	count := d.GetPatternCount()
	if count == 0 {
		t.Error("SQL injection detector should have patterns")
	}
}
