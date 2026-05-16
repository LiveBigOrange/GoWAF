local counter = 0

request = function()
  counter = counter + 1
  local paths = {
    "/",
    "/index.html",
    "/api/users?page=1",
    "/static/css/main.css",
    "/health"
  }
  local path = paths[(counter % #paths) + 1]
  local methods = {"GET", "HEAD", "OPTIONS"}
  local method = methods[(counter % #methods) + 1]
  return wrk.format(method, path, {
    ["User-Agent"] = "Mozilla/5.0",
    ["Accept"] = "*/*",
    ["Connection"] = "keep-alive"
  })
end
