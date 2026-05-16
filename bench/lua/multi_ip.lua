local counter = 0

request = function()
  counter = counter + 1
  local a = math.floor(counter / 65536) % 256
  local b = math.floor(counter / 256) % 256
  local c = counter % 256
  local ip = string.format("10.%d.%d.%d", a, b, c)
  return wrk.format("GET", "/api/data?page=1", {
    ["X-Forwarded-For"] = ip,
    ["User-Agent"] = "Mozilla/5.0"
  })
end
