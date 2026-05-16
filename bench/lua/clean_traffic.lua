local paths = {
  "/", "/index.html", "/about", "/api/users?page=1",
  "/api/products?category=electronics&sort=price",
  "/static/css/main.css", "/static/js/app.js",
  "/images/logo.png", "/favicon.ico", "/health"
}
local counter = 0

request = function()
  counter = counter + 1
  local path = paths[(counter % #paths) + 1]
  return wrk.format("GET", path, {
    ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    ["Accept"] = "text/html,application/xhtml+xml",
    ["Accept-Language"] = "zh-CN,zh;q=0.9",
    ["Connection"] = "keep-alive"
  })
end
