package logging

//go:generate sh -c "go run go.uber.org/mock/mockgen -package logging -self_package github.com/refraction-networking/uquic/logging -destination mock_connection_tracer_test.go github.com/refraction-networking/uquic/logging ConnectionTracer"
//go:generate sh -c "go run go.uber.org/mock/mockgen -package logging -self_package github.com/refraction-networking/uquic/logging -destination mock_tracer_test.go github.com/refraction-networking/uquic/logging Tracer"
