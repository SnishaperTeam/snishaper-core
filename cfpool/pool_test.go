package cfpool

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestGetAllIPsWithStatsReturnsSnapshot 验证返回值是快照而非共享指针，
// 与并发状态更新（失败上报/健康检查写回）同时运行不被 race detector 报警。
func TestGetAllIPsWithStatsReturnsSnapshot(t *testing.T) {
	pool := NewCloudflarePool([]string{"1.2.3.4", "5.6.7.8"})
	defer pool.Stop()

	// 先让池内有可读状态。
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_ = srv // 仅占位；本测试不拨号，状态字段由 ReportFailure 直接驱动

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				pool.ReportFailure("1.2.3.4")
				pool.ReportSuccess("5.6.7.8")
			}
		}
	}()

	for i := 0; i < 200; i++ {
		for _, s := range pool.GetAllIPsWithStats() {
			_ = s.IP + s.Latency + s.LastCheck
			_ = s.LatencyVal + time.Since(s.LastCheckTime)
			_ = s.Failures
		}
	}
	close(stop)
	wg.Wait()
}
