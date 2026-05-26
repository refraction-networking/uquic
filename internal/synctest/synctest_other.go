// [uQUIC] fallback for Go 1.24 without GOEXPERIMENT=synctest and older Go versions
//go:build (!go1.24) || (go1.24 && !go1.25 && !goexperiment.synctest)

package synctest

import "testing"

func Test(t *testing.T, f func(t *testing.T)) {
	f(t)
}

func Wait() {}
