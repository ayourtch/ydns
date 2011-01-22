#define LUA_LIB

#include "lua.h"
#include "lauxlib.h"

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "dns.h"

unsigned char buf[1500];

static void Lseti(lua_State *L, char *key, int value) {
  lua_pushstring(L, key);
  lua_pushinteger(L, value);
  lua_settable(L, -3);
}

static void Lsets(lua_State *L, char *key, char *value) {
  lua_pushstring(L, key);
  lua_pushstring(L, value);
  lua_settable(L, -3);
}

static void Lsetls(lua_State *L, char *key, char *value, int vlen) {
  lua_pushstring(L, key);
  lua_pushlstring(L, value, vlen);
  lua_settable(L, -3);
}

static int my_header(void *arg, int req_id, int trunc, int errcode, int qdcount, int ancount, int nscount, int arcount) {
  lua_State *L = arg;
  Lseti(L, "xid", req_id);
  Lseti(L, "trunc", trunc);
  Lseti(L, "errcode", errcode);
  Lseti(L, "qdcount", qdcount);
  Lseti(L, "ancount", ancount);
  Lseti(L, "nscount", nscount);
  Lseti(L, "arcount", arcount);
  return 1;
}
static int my_question(void *arg, char *domainname, int type, int class) {
  lua_State *L = arg;
  lua_pushstring(L, "q"); // for later to put this into parent table
  lua_createtable(L, 0, 3);
  Lsets(L, "name", domainname);
  Lseti(L, "type", type);
  Lseti(L, "class", class);
  lua_settable(L, -3); // assign to parent table
  return 1;
}
static int my_a_rr(void *arg, char *domainname, uint32_t ttl, uint32_t addr) {
  char dest[INET_ADDRSTRLEN+1] = { 0 };
  lua_State *L = arg;
  inet_ntop(AF_INET, &addr, dest, sizeof(dest));
  lua_pushinteger(L, 1+lua_objlen(L, -1)); // index for this table in the parent
  lua_createtable(L, 0, 6);
  Lsets(L, "type", "A");
  Lsets(L, "name", domainname);
  Lsets(L, "val", dest);
  Lsetls(L, "raw", (void*)&addr, sizeof(addr));
  Lseti(L, "ttl", ttl);
  Lseti(L, "expire", time(NULL) + ttl);
  lua_settable(L, -3);
  return 1;
}
static int my_aaaa_rr(void *arg, char *domainname, uint32_t ttl, uint8_t *addr) {
  char dest[INET6_ADDRSTRLEN+1] = { 0 };
  lua_State *L = arg;
  inet_ntop(AF_INET6, addr, dest, sizeof(dest));
  lua_pushinteger(L, 1+lua_objlen(L, -1)); // index for this table in the parent
  lua_createtable(L, 0, 6);
  Lsets(L, "type", "AAAA");
  Lsets(L, "name", domainname);
  Lsets(L, "val", dest);
  Lsetls(L, "raw", (void*)addr, 16);
  Lseti(L, "ttl", ttl);
  Lseti(L, "expire", time(NULL) + ttl);
  lua_settable(L, -3);
  return 1;
}
static int my_cname_rr(void *arg, char *domainname, uint32_t ttl, char *cname) {
  lua_State *L = arg;
  lua_pushinteger(L, 1+lua_objlen(L, -1)); // index for this table in the parent
  lua_createtable(L, 0, 6);
  Lsets(L, "type", "CNAME");
  Lsets(L, "name", domainname);
  Lsets(L, "val", cname);
  Lsets(L, "raw", cname);
  Lseti(L, "ttl", ttl);
  Lseti(L, "expire", time(NULL) + ttl);
  lua_settable(L, -3);
  return 1;
}


decode_callbacks_t my_cb = {
  .process_header = my_header,
  .process_question = my_question,
  .process_a_rr = my_a_rr,
  .process_aaaa_rr = my_aaaa_rr,
  .process_cname_rr = my_cname_rr,
};




static int Lydns_encode_request(lua_State *L) {
  const char *name = luaL_checkstring(L, 1);
  int qtype = luaL_checkint(L, 2);
  int xid = luaL_checkint(L, 3); 
  unsigned char *p = buf;
  if(ydns_encode_request(&p, sizeof(buf), qtype, (char *)name, xid)) {
    lua_pushlstring(L, (void *)buf, p-buf);
  } else {
    lua_pushnil(L);
  }
  return 1;  
}

static int Lydns_decode_reply(lua_State *L) {
  const char *buf = luaL_checkstring(L, 1);
  int len  = lua_objlen(L, 1);
  lua_createtable(L, 5, 5);
  int ret = ydns_decode_reply((void*)buf, len, (void *)L, &my_cb);
  Lseti(L, "status", ret);
  return 1;
}

static const luaL_reg funcs[] = {
    {"encode_request",    Lydns_encode_request},
    {"decode_reply", Lydns_decode_reply},
    {NULL,      NULL}
};

LUALIB_API int luaopen_ydns(lua_State *L) {
  luaL_register(L, "ydns", funcs);
  return 1;
}

