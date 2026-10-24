package utils

import (
	"fmt"
	"runtime/debug"
)

var panicLogger = NewLogger("PANIC")

// SafeGo runs a goroutine with panic recovery (RULES.md §4.4)
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				panicLogger.Error("Goroutine panic recovered: name=%s panic=%v\nstack=%s", name, r, string(stack))
			}
		}()
		fn()
	}()
}

// SafeGoWithRestart runs a goroutine with panic recovery and automatic restart
func SafeGoWithRestart(name string, fn func()) {
	SafeGo(name, func() {
		for {
			func() {
				defer func() {
					if r := recover(); r != nil {
						stack := debug.Stack()
						panicLogger.Error("Goroutine panic (restarting): name=%s panic=%v\nstack=%s", name, r, string(stack))
					}
				}()
				fn()
			}()
		}
	})
}

// MustNotPanic wraps a function call and converts panic to error
func MustNotPanic(operation string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			err = fmt.Errorf("panic in %s: %v\nstack: %s", operation, r, string(stack))
			panicLogger.Error("Panic converted to error: %v", err)
		}
	}()
	return fn()
}
