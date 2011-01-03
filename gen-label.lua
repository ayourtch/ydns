
print([[
%%{

machine dns;

label = ]])

acc = {}
for i = 1,63 do
  local delim = "|"
  local innards = ''
  if (i == 63) then
    delim = ";"
  end 
  we_are_rfc_police = true
  if we_are_rfc_police then
    if i == 0 then 
      innards = "ll"
    elseif i == 1 then
      innards = "ll ld"
    else
      innards = "ll ldh{" .. i .. "} ld"
    end
  else
    innards = "ldh{" .. i .. "}"
  end
  print("    " .. i .. " " .. innards .. 
        " @{ debug(DNS_LABEL,\"LBL"..i.."\\n\"); seglen = " .. i .. "; } " .. delim)
end

print([[

}%%

]])
