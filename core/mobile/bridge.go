//go:build android

package main

/*
#include <jni.h>
#include <stdlib.h>

int cb_protect(int fd);
void cb_state(int testing);
void cb_result(int idx, int ms);
void cb_core_died(void);
jstring new_jstring(JNIEnv *env, const char *s);
char *go_string(JNIEnv *env, jstring s);
char *go_bytes(JNIEnv *env, jbyteArray a, int *n);
void free_bytes(char *p, int n);
*/
import "C"

import (
	"sync/atomic"
	"syscall"
	"unsafe"

	"arc/core/internal/dns"
	"arc/core/internal/engine"
	"arc/core/internal/outbound"
	"arc/core/internal/protect"
	"arc/core/internal/router"
	"arc/core/internal/store"
)

func main() {}

func toModifiedUTF8(s string) []byte {
	b := make([]byte, 0, len(s)+8)
	for _, r := range s {
		switch {
		case r == 0:
			b = append(b, 0xC0, 0x80)
		case r > 0xFFFF:
			r -= 0x10000
			for _, u := range [2]rune{0xD800 + (r >> 10), 0xDC00 + (r & 0x3FF)} {
				b = append(b, byte(0xE0|(u>>12)), byte(0x80|((u>>6)&0x3F)), byte(0x80|(u&0x3F)))
			}
		default:
			b = append(b, string(r)...)
		}
	}
	return append(b, 0)
}

func jstr(env *C.JNIEnv, s string) C.jstring {
	b := toModifiedUTF8(s)
	return C.new_jstring(env, (*C.char)(unsafe.Pointer(&b[0])))
}

type jniLatency struct{}

func (jniLatency) OnStateChanged(t bool) {
	v := C.int(0)
	if t {
		v = 1
	}
	C.cb_state(v)
}
func (jniLatency) OnNodeResult(i, ms int) { C.cb_result(C.int(i), C.int(ms)) }

func jniProtect(fd int) bool { return C.cb_protect(C.int(fd)) != 0 }

func goString(env *C.JNIEnv, s C.jstring) string {
	p := C.go_string(env, s)
	if p == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p)
}

func jbool(b bool) C.jboolean {
	if b {
		return C.JNI_TRUE
	}
	return C.JNI_FALSE
}

// shutdownGate replaces a sync.WaitGroup that could panic when stopCore
// raced Wait callers on other JNI threads.
var shutdownGate engine.ShutdownGate

var switchGen atomic.Uint64

//export Java_com_arc_app_Native_startCore
func Java_com_arc_app_Native_startCore(env *C.JNIEnv, cls C.jclass, tunFd, regionIdx, nodeIdx C.jint) C.jstring {
	shutdownGate.Wait()
	if !store.Loaded() {
		_ = syscall.Close(int(tunFd))
		return jstr(env, "节点表未加载")
	}
	switchGen.Add(1)
	outbound.SwitchActive(int(regionIdx), int(nodeIdx))

	outbound.ClearEndpointCache()
	dns.ClearCache()
	engine.SetOnUnexpectedStop(func() { C.cb_core_died() })
	if err := engine.GlobalTun.Start(int(tunFd)); err != nil {
		engine.SetOnUnexpectedStop(nil)
		return jstr(env, err.Error())
	}
	outbound.Prewarm()
	dns.PrewarmDoH()
	return jstr(env, "")
}

//export Java_com_arc_app_Native_stopCore
func Java_com_arc_app_Native_stopCore(env *C.JNIEnv, cls C.jclass) {
	engine.SetOnUnexpectedStop(nil)
	switchGen.Add(1)
	u, m := engine.GlobalTun.StopAndRelease()
	shutdownGate.Go(func() {
		engine.GlobalTun.FinishStop(u, m)
		outbound.CloseLiveConns()
		outbound.ClearAnyTLSPool()
		dns.OnNetworkChanged()
		_ = router.FlushLearned()
	})
}

//export Java_com_arc_app_Native_isCoreRunning
func Java_com_arc_app_Native_isCoreRunning(env *C.JNIEnv, cls C.jclass) C.jboolean {
	return jbool(engine.GlobalTun.IsRunning())
}

//export Java_com_arc_app_Native_switchNode
func Java_com_arc_app_Native_switchNode(env *C.JNIEnv, cls C.jclass, regionIdx, nodeIdx C.jint) {
	// F11: intentionally skip ClearCache / FakeIP invalidate — node switch must not drop domain class / FakeIP.
	shutdownGate.Wait()
	gen := switchGen.Add(1)
	outbound.SwitchActive(int(regionIdx), int(nodeIdx))
	if switchGen.Load() != gen {
		return
	}
	outbound.CloseLiveConns()
	if switchGen.Load() != gen {
		return
	}
	engine.GlobalTun.ResetUDP()
	if switchGen.Load() != gen {
		return
	}
	outbound.Prewarm()
	dns.PrewarmDoH()
}

//export Java_com_arc_app_Native_getCatalog
func Java_com_arc_app_Native_getCatalog(env *C.JNIEnv, cls C.jclass) C.jstring {
	return jstr(env, string(store.Get().UIJSON()))
}

//export Java_com_arc_app_Native_loadNodes
func Java_com_arc_app_Native_loadNodes(env *C.JNIEnv, cls C.jclass, table C.jbyteArray) C.jstring {
	if engine.GlobalTun.IsRunning() {
		return jstr(env, "核心运行中，节点表稍后加载")
	}
	var n C.int
	p := C.go_bytes(env, table, &n)
	if p == nil {
		return jstr(env, "节点表读取失败")
	}
	b := C.GoBytes(unsafe.Pointer(p), n)
	C.free_bytes(p, n)
	defer clear(b)
	engine.CancelBatchTest()
	if err := store.Load(b); err != nil {
		return jstr(env, err.Error())
	}
	outbound.ClearEndpointCache()
	return jstr(env, "")
}

//export Java_com_arc_app_Native_testRegionLatencies
func Java_com_arc_app_Native_testRegionLatencies(env *C.JNIEnv, cls C.jclass, regionIdx C.jint) {
	engine.StartBatchTest(int(regionIdx), jniLatency{})
}

//export Java_com_arc_app_Native_cancelBatchLatencyTest
func Java_com_arc_app_Native_cancelBatchLatencyTest(env *C.JNIEnv, cls C.jclass) {
	engine.CancelBatchTest()
}

//export Java_com_arc_app_Native_notifyNetworkChanged
func Java_com_arc_app_Native_notifyNetworkChanged(env *C.JNIEnv, cls C.jclass, kind C.jint) {
	shutdownGate.Wait()
	engine.ApplyNetworkChange(int(kind))
	outbound.Prewarm()
	dns.PrewarmDoH()
}

//export Java_com_arc_app_Native_setDataDir
func Java_com_arc_app_Native_setDataDir(env *C.JNIEnv, cls C.jclass, dir C.jstring) {
	d := goString(env, dir)
	outbound.SetDataDir(d)
	router.SetDataDir(d)
}

//export Java_com_arc_app_Native_setProtector
func Java_com_arc_app_Native_setProtector(env *C.JNIEnv, cls C.jclass, enabled C.jboolean) {
	if enabled != 0 {
		protect.Set(jniProtect)
	} else {
		protect.Set(nil)
	}
}

//export Java_com_arc_app_Native_setUnderlying
func Java_com_arc_app_Native_setUnderlying(env *C.JNIEnv, cls C.jclass, servers C.jstring, v6 C.jint) {
	dns.SetUnderlying(goString(env, servers), int(v6))
}
