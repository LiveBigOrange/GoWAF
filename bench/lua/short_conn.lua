request = function()
  return wrk.format("GET", "/", {
    ["Connection"] = "close"
  })
end
