package subscription

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SnishaperTeam/snishaper-core/config"
)

// testSubscriptionYAML 是一个能被解析器接受的最小订阅体，供 Store 路径使用。
const testSubscriptionYAML = `proxies:
  - name: "HK-01"
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "pw"
proxy-groups:
  - name: Proxy
    type: select
    proxies: ["HK-01"]
rules:
  - MATCH,Proxy
`

// captureUserAgent 起一个只关心 User-Agent 的测试服务器，返回它收到的值。
// 走真实 HTTP 请求而不是直接调订阅构造字符串，这样一旦有人再写死产品名
// （或改动 fetchWith 的取值），测试就会失败。
func captureUserAgent(t *testing.T) (url string, seen *string) {
	t.Helper()
	got := new(string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("User-Agent")
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=3")
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(testSubscriptionYAML))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, got
}

// 订阅请求必须带上调用方自己的产品名，而不是库里写死的参考产品名。
func TestFetchUserAgentUsesBrand(t *testing.T) {
	url, seen := captureUserAgent(t)

	if _, _, err := Fetch(url, "", WithProductName("FlowWeaver")); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if want := "clash-verge/v2.0 FlowWeaver"; *seen != want {
		t.Errorf("User-Agent = %q, want %q", *seen, want)
	}
}

// 不传 option 时回落到参考产品名：旧调用方的行为不变。
func TestFetchUserAgentDefaultsToReferenceProduct(t *testing.T) {
	url, seen := captureUserAgent(t)

	if _, _, err := Fetch(url, ""); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if want := clashVergeUserAgentPrefix + config.DefaultProductName; *seen != want {
		t.Errorf("User-Agent = %q, want %q", *seen, want)
	}
	if strings.Contains(*seen, "FlowWeaver") {
		t.Errorf("default User-Agent must not name another embedder: %q", *seen)
	}
}

// Store 路径同样要带品牌：app 层用的是 NewStore，不是包级 Fetch。
func TestStoreFetchUserAgentUsesBrand(t *testing.T) {
	url, seen := captureUserAgent(t)

	s := NewStore(t.TempDir()+"/subscriptions.json", nil, WithBrand(config.Brand{Name: "FlowWeaver"}))
	entry, err := s.Add("test", url)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if entry == nil || len(entry.Nodes) == 0 {
		t.Fatalf("expected parsed nodes, got %+v", entry)
	}

	if want := "clash-verge/v2.0 FlowWeaver"; *seen != want {
		t.Errorf("Store User-Agent = %q, want %q", *seen, want)
	}
}

// 前导/尾随空白要被 Resolve 清掉，否则会拼出奇怪的 UA。
func TestFetchUserAgentTrimsBrand(t *testing.T) {
	url, seen := captureUserAgent(t)

	if _, _, err := Fetch(url, "", WithBrand(config.Brand{Name: "  FlowWeaver  "})); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if want := "clash-verge/v2.0 FlowWeaver"; *seen != want {
		t.Errorf("User-Agent = %q, want %q", *seen, want)
	}
}
