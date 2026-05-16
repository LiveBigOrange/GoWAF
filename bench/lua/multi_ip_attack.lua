local counter = 0

request = function()
  counter = counter + 1
  local a = math.floor(counter / 65536) % 256
  local b = math.floor(counter / 256) % 256
  local c = counter % 256
  local ip = string.format("10.%d.%d.%d", a, b, c)
  local attacks = {
    "/api/login?user=admin' OR 1=1--",
    "/search?q=<script>alert(1)</script>",
    "/api/ping?host=;cat /etc/passwd",
    "/files/../../../etc/passwd"
  }
  local path = attacks[(counter % #attacks) + 1]
  return wrk.format("GET", path, {
    ["X-Forwarded-For"] = ip,
    ["User-Agent"] = "Mozilla/5.0"
  })
end
