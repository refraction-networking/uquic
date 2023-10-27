//go:build gomock || generate

package mocks

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mockquic -destination quic/stream.go github.com/refraction-networking/uquic Stream"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mockquic -destination quic/early_conn_tmp.go github.com/refraction-networking/uquic EarlyConnection && sed 's/qtls.ConnectionState/quic.ConnectionState/g' quic/early_conn_tmp.go > quic/early_conn.go && rm quic/early_conn_tmp.go && go run golang.org/x/tools/cmd/goimports -w quic/early_conn.go"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocks -destination short_header_sealer.go github.com/refraction-networking/uquic/internal/handshake ShortHeaderSealer"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocks -destination short_header_opener.go github.com/refraction-networking/uquic/internal/handshake ShortHeaderOpener"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocks -destination long_header_opener.go github.com/refraction-networking/uquic/internal/handshake LongHeaderOpener"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocks -destination crypto_setup_tmp.go github.com/refraction-networking/uquic/internal/handshake CryptoSetup && sed -E 's~github.com/quic-go/qtls[[:alnum:]_-]*~github.com/refraction-networking/uquic/internal/qtls~g; s~qtls.ConnectionStateWith0RTT~qtls.ConnectionState~g' crypto_setup_tmp.go > crypto_setup.go && rm crypto_setup_tmp.go && go run golang.org/x/tools/cmd/goimports -w crypto_setup.go"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocks -destination stream_flow_controller.go github.com/refraction-networking/uquic/internal/flowcontrol StreamFlowController"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocks -destination congestion.go github.com/refraction-networking/uquic/internal/congestion SendAlgorithmWithDebugInfos"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocks -destination connection_flow_controller.go github.com/refraction-networking/uquic/internal/flowcontrol ConnectionFlowController"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mockackhandler -destination ackhandler/sent_packet_handler.go github.com/refraction-networking/uquic/internal/ackhandler SentPacketHandler"
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mockackhandler -destination ackhandler/received_packet_handler.go github.com/refraction-networking/uquic/internal/ackhandler ReceivedPacketHandler"

// The following command produces a warning message on OSX, however, it still generates the correct mock file.
// See https://github.com/golang/mock/issues/339 for details.
//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package mocktls -destination tls/client_session_cache.go crypto/tls ClientSessionCache"
