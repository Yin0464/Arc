package outbound

import (
	"testing"
)

func TestClientHelloIDOfficialNames(t *testing.T) {
	for _, name := range []string{
		"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
		"chrome120", "firefox120", "safari16",
		"chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle",
		"chrome_pq", "chrome_pq_psk", "randomized", "random",
	} {
		if _, ok := clientHelloID(name); !ok {
			t.Fatalf("missing fingerprint %s", name)
		}
	}
	if _, ok := clientHelloID(""); ok {
		t.Fatal("empty should be off")
	}
	if _, ok := clientHelloID("none"); ok {
		t.Fatal("none should be off")
	}
	if _, ok := clientHelloID("not-a-browser"); ok {
		t.Fatal("unknown should be off")
	}
}
