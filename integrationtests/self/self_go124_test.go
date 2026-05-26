//go:build !go1.25

package self_test

import tls "github.com/refraction-networking/utls" // [uQUIC]

func getCurveID(connState tls.ConnectionState) tls.CurveID {
	return 0
}
