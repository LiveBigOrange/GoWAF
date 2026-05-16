local bodies = {
  "username=admin' OR 1=1--&password=test",
  "search=<script>alert(document.cookie)</script>",
  "cmd=;cat /etc/passwd",
  "file=../../../etc/shadow",
  "url=http://169.254.169.254/metadata",
  '{"query":"SELECT * FROM users WHERE id=1 OR 1=1"}',
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
  '{"$or":[{"username":"admin"},{"username":{"$regex":"admin.*"}}]}',
  '{"template":"{{7*7}}","name":"{{config.__class__.__init__.__globals__}}"}',
  "data=normal_clean_input_data"
}
local counter = 0

request = function()
  counter = counter + 1
  local body = bodies[(counter % #bodies) + 1]
  return wrk.format("POST", "/api/submit", {
    ["Content-Type"] = "application/x-www-form-urlencoded",
    ["User-Agent"] = "Mozilla/5.0",
    ["Accept"] = "application/json"
  }, body)
end
