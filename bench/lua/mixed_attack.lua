local attacks = {
  "GET /api/login?user=admin' OR 1=1--",
  "GET /api/search?q=1' UNION SELECT null--",
  "POST /api/data",
  "GET /search?q=<script>alert(1)</script>",
  "GET /comment?text=<img src=x onerror=alert(1)>",
  "GET /api/ping?host=;cat /etc/passwd",
  "GET /api/exec?cmd=|id",
  "GET /files/../../../etc/passwd",
  "GET /download?file=..%2f..%2fetc/passwd",
  "GET /proxy?url=http://169.254.169.254/latest/meta-data/",
  "GET /fetch?target=http://127.0.0.1:8080/admin",
  "GET /admin/config.php",
  "GET /.env",
  "GET /wp-admin/",
  "GET /actuator/health",
  "GET /api/users?page=1",
  "GET /index.html"
}
local counter = 0

request = function()
  counter = counter + 1
  local attack = attacks[(counter % #attacks) + 1]
  local method, path = attack:match("^(%S+)%s+(%S+)")

  if method == "POST" then
    return wrk.format("POST", path, {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["User-Agent"] = "Mozilla/5.0"
    }, "user=admin' OR 1=1--&pass=test")
  else
    return wrk.format(method, path, {
      ["User-Agent"] = "Mozilla/5.0"
    })
  end
end
