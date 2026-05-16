local counter = 0

request = function()
  counter = counter + 1
  local sizes = {1024, 10240, 51200, 102400, 204800, 512000, 1048576}
  local size = sizes[(counter % #sizes) + 1]
  local path = string.format("/api/upload?size=%d", size)
  local body = string.rep("A", size)
  return wrk.format("POST", path, {
    ["Content-Type"] = "application/octet-stream",
    ["Content-Length"] = tostring(size),
    ["User-Agent"] = "Mozilla/5.0"
  }, body)
end
