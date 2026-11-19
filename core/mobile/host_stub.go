//go:build !android

package main

// Host stub so `go test ./...` does not compile the JNI cgo bridge (jni.h / NDK).
// Android c-shared build uses bridge.go + bridge.c via build.sh (GOOS=android).
