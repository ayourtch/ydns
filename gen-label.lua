
print([[
%%{

machine dns;

label = ]])

acc = {}
for i = 1,63 do
  local delim = "|"
  if (i == 63) then
    delim = ";"
  end 
  we_are_rfc_police = true
  if we_are_rfc_police then
    if i == 0 then 
      table.insert(acc, "ll")
    elseif i == 1 then
      table.insert(acc, "ld")
    else
      table.insert(acc, 2, "ldh")
    end
  else
    table.insert(acc, "ldh")
  end
  print("    " .. i .. " " .. table.concat(acc, " ") .. 
        " @{ printf(\"LBL"..i.."\\n\"); seglen = " .. i .. "; } " .. delim)
end

print([[

}%%

]])
