
print([[
%%{

machine dns;

ardata = ]])

acc = {}

top_i = 1
for i = 0,top_i do
  for j = 0,255 do
    local delim = "|"
    local k = i*256+j
    if (i == top_i) and (j == 255) then
      delim = ";"
    end 
    print("    " .. i .. " " .. j .. " " .. table.concat(acc, " ") .. 
          " @{ arlen = " .. k .. "; } " .. delim)
    table.insert(acc, "x");
  end
end

print([[

}%%

]])
