local counter = 0

request = function()
  counter = counter + 1
  local scans = {
    "GET /admin",
    "GET /backup.sql",
    "GET /.git/config",
    "GET /.env",
    "GET /wp-config.php",
    "GET /phpmyadmin/",
    "GET /debug/",
    "GET /actuator/env",
    "GET /server-status",
    "GET /.DS_Store",
    "GET /config.yml",
    "GET /api/swagger.json",
    "GET /console/",
    "GET /elmah.axd",
    "GET /trace.axd",
    "GET /robots.txt",
    "GET /sitemap.xml",
    "GET /crossdomain.xml",
    "GET /WEB-INF/web.xml",
    "GET /META-INF/MANIFEST.MF"
  }
  local req = scans[(counter % #scans) + 1]
  local method, path = req:match("^(%S+)%s+(%S+)")
  return wrk.format(method, path, {
    ["User-Agent"] = "DirBuster-1.0-RC1",
    ["Accept"] = "*/*"
  })
end
