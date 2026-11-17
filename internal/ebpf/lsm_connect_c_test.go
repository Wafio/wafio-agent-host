package ebpf

import "testing"

// TestLSMConnectIPv4Target compiles the socket_connect address helper of
// wafio_lsm.c natively and checks which connects the IPv4 blocklist sees: an
// AF_INET destination, and an AF_INET6 one carrying an IPv4-mapped address
// (::ffff:a.b.c.d), which a dual-stack socket connects over IPv4. Before the
// mapped-address check the hook returned early for anything but AF_INET, so
// connect(AF_INET6, ::ffff:203.0.113.9) reached a blocklisted IPv4 address.
func TestLSMConnectIPv4Target(t *testing.T) {
	src := `typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef uint64_t __u64;
typedef __u16 __be16; typedef __u32 __be32;
#define BPF_CORE_READ(p, f) ((p)->f)
static long bpf_core_read(void *dst, __u32 sz, const void *src) { memcpy(dst, src, sz); return 0; }
/* Linux layouts (vmlinux.h), not the host's BSD sockaddr with sa_len. */
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct in_addr { __be32 s_addr; };
struct sockaddr_in { unsigned short sin_family; __be16 sin_port; struct in_addr sin_addr; unsigned char __pad[8]; };
struct in6_addr { union { __u8 u6_addr8[16]; __be16 u6_addr16[8]; __be32 u6_addr32[4]; } in6_u; };
struct sockaddr_in6 { unsigned short sin6_family; __be16 sin6_port; __be32 sin6_flowinfo; struct in6_addr sin6_addr; __u32 sin6_scope_id; };
` + bpfSourceDefines(t, "wafio_lsm.c", "AF_", "LSM_SIN6_LEN") +
		bpfSourceHelper(t, "wafio_lsm.c", "lsm_connect_ipv4") + `
/* The kernel hands the hook a sockaddr_storage copy of the user buffer. */
static unsigned char storage[128];
static void v4(unsigned short family, const __u8 ip[4], __u16 port) {
  memset(storage, 0xAA, sizeof storage); /* stale bytes past addrlen */
  struct sockaddr_in *s = (struct sockaddr_in *)storage;
  s->sin_family = family; s->sin_port = (__be16)((port >> 8) | (port << 8)); memcpy(&s->sin_addr, ip, 4);
}
static void v6(const __u8 ip[16], __u16 port) {
  memset(storage, 0xAA, sizeof storage);
  struct sockaddr_in6 *s = (struct sockaddr_in6 *)storage;
  s->sin6_family = AF_INET6; s->sin6_port = (__be16)((port >> 8) | (port << 8)); s->sin6_flowinfo = 0;
  memcpy(&s->sin6_addr, ip, 16); s->sin6_scope_id = 0;
}
static void check(const char *name, int addrlen) {
  __be32 addr = 0; __be16 port = 0; __u16 family = 0;
  int ok = lsm_connect_ipv4((struct sockaddr *)storage, addrlen, &addr, &port, &family);
  const __u8 *b = (const __u8 *)&addr;
  if (ok)
    printf("%s ok %u.%u.%u.%u:%u family=%u\n", name, (unsigned)b[0], (unsigned)b[1], (unsigned)b[2], (unsigned)b[3], (unsigned)(__u16)((port >> 8) | (port << 8)), (unsigned)family);
  else
    printf("%s none\n", name);
}
int main(void) {
  const __u8 blocked[4] = { 203, 0, 113, 9 };
  const __u8 mapped[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 203,0,113,9 };
  const __u8 compat[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 203,0,113,9 };        /* ::203.0.113.9, native IPv6 */
  const __u8 native[16] = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1 }; /* 2001:db8::1 */
  const __u8 near[16]   = { 0,0,0,0, 0,0,0,0, 0,1,0xff,0xff, 203,0,113,9 };  /* one bit off ::ffff:0:0/96 */
  v4(AF_INET, blocked, 443);  check("inet", 16);
  v4(AF_INET, blocked, 443);  check("inet_short", 8);
  v6(mapped, 443);            check("inet6_mapped", 28);
  v6(mapped, 443);            check("inet6_mapped_rfc2133", 24);
  v6(mapped, 443);            check("inet6_mapped_short", 23);
  v6(compat, 443);            check("inet6_compat", 28);
  v6(native, 443);            check("inet6_native", 28);
  v6(near, 443);              check("inet6_near_mapped", 28);
  v4(1 /* AF_UNIX */, blocked, 0); check("unix", 110);
  return 0;
}
`
	got := runNativeC(t, "lsm_connect", src)
	want := `inet ok 203.0.113.9:443 family=2
inet_short none
inet6_mapped ok 203.0.113.9:443 family=10
inet6_mapped_rfc2133 ok 203.0.113.9:443 family=10
inet6_mapped_short none
inet6_compat none
inet6_native none
inet6_near_mapped none
unix none
`
	if got != want {
		t.Fatalf("socket_connect IPv4 target:\n got:\n%s\nwant:\n%s", got, want)
	}
}
