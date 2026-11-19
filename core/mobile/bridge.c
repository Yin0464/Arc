//go:build android

// Arc 手写 JNI 胶水（与 bridge.go 配对）：缓存 JavaVM/Native 方法 ID，
// 供 Go 回调 protect、测速进度/结果、核心死亡；线程 attach 在线程退出时再 Detach。
#include <jni.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>

static JavaVM *g_vm;
static jclass g_cls;
static jmethodID g_protect, g_state, g_result, g_died;
static pthread_key_t g_detach_key;

// Detach only when the thread exits. DetachCurrentThread after every protect()
// aborts the process if a thread dies still attached, and attaching per socket
// dominates the dial path.
static void detach_thread(void *arg) {
	(void)arg;
	if (g_vm != NULL) (*g_vm)->DetachCurrentThread(g_vm);
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
	JNIEnv *env;
	g_vm = vm;
	if (pthread_key_create(&g_detach_key, detach_thread) != 0) return JNI_ERR;
	if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
	jclass c = (*env)->FindClass(env, "com/arc/app/Native");
	if (c == NULL) return JNI_ERR;
	g_cls = (jclass)(*env)->NewGlobalRef(env, c);
	(*env)->DeleteLocalRef(env, c);
	g_protect = (*env)->GetStaticMethodID(env, g_cls, "protect", "(I)Z");
	g_state = (*env)->GetStaticMethodID(env, g_cls, "onLatencyState", "(Z)V");
	g_result = (*env)->GetStaticMethodID(env, g_cls, "onLatencyResult", "(II)V");
	g_died = (*env)->GetStaticMethodID(env, g_cls, "onCoreDied", "()V");
	if (!g_protect || !g_state || !g_result || !g_died) return JNI_ERR;
	return JNI_VERSION_1_6;
}

// Obtain a JNIEnv for the current (possibly Go-created) thread.
// Threads we attach are detached by detach_thread, not after the call.
static JNIEnv *get_env(void) {
	JNIEnv *env = NULL;
	if (g_vm == NULL) return NULL;
	jint r = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
	if (r == JNI_EDETACHED) {
		if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return NULL;
		// Already-attached threads (the main thread) must not be detached on exit.
		pthread_setspecific(g_detach_key, (void *)1);
	} else if (r != JNI_OK) {
		return NULL;
	}
	return env;
}

static void done_env(JNIEnv *env) {
	if (env != NULL && (*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

int cb_protect(int fd) {
	JNIEnv *env = get_env();
	if (env == NULL) return 0;
	jboolean ok = (*env)->CallStaticBooleanMethod(env, g_cls, g_protect, (jint)fd);
	if ((*env)->ExceptionCheck(env)) ok = JNI_FALSE;
	done_env(env);
	return ok ? 1 : 0;
}

void cb_state(int testing) {
	JNIEnv *env = get_env();
	if (env == NULL) return;
	(*env)->CallStaticVoidMethod(env, g_cls, g_state, testing ? JNI_TRUE : JNI_FALSE);
	done_env(env);
}

void cb_result(int idx, int ms) {
	JNIEnv *env = get_env();
	if (env == NULL) return;
	(*env)->CallStaticVoidMethod(env, g_cls, g_result, (jint)idx, (jint)ms);
	done_env(env);
}

void cb_core_died(void) {
	JNIEnv *env = get_env();
	if (env == NULL) return;
	(*env)->CallStaticVoidMethod(env, g_cls, g_died);
	done_env(env);
}

jstring new_jstring(JNIEnv *env, const char *s) {
	return (*env)->NewStringUTF(env, s);
}

// go_string copies a Java string's (modified) UTF-8 into a malloc'd C string; caller frees.
char *go_string(JNIEnv *env, jstring s) {
	if (s == NULL) return NULL;
	const char *u = (*env)->GetStringUTFChars(env, s, NULL);
	if (u == NULL) return NULL;
	char *r = strdup(u);
	(*env)->ReleaseStringUTFChars(env, s, u);
	return r;
}

// go_bytes copies a Java byte[] into a malloc'd buffer; release with free_bytes.
char *go_bytes(JNIEnv *env, jbyteArray a, int *n) {
	if (a == NULL) return NULL;
	jsize l = (*env)->GetArrayLength(env, a);
	char *p = malloc(l > 0 ? (size_t)l : 1);
	if (p == NULL) return NULL;
	(*env)->GetByteArrayRegion(env, a, 0, l, (jbyte *)p);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		free(p);
		return NULL;
	}
	*n = (int)l;
	return p;
}

// free_bytes wipes a buffer from go_bytes before freeing it.
void free_bytes(char *p, int n) {
	if (p == NULL) return;
	volatile char *v = p;
	for (int i = 0; i < n; i++) v[i] = 0;
	free(p);
}
