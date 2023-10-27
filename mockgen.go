//go:build gomock || generate

package quic

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_send_conn_test.go github.com/refraction-networking/uquic SendConn"
type SendConn = sendConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_raw_conn_test.go github.com/refraction-networking/uquic RawConn"
type RawConn = rawConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_sender_test.go github.com/refraction-networking/uquic Sender"
type Sender = sender

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_stream_internal_test.go github.com/refraction-networking/uquic StreamI"
type StreamI = streamI

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_crypto_stream_test.go github.com/refraction-networking/uquic CryptoStream"
type CryptoStream = cryptoStream

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_receive_stream_internal_test.go github.com/refraction-networking/uquic ReceiveStreamI"
type ReceiveStreamI = receiveStreamI

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_send_stream_internal_test.go github.com/refraction-networking/uquic SendStreamI"
type SendStreamI = sendStreamI

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_stream_getter_test.go github.com/refraction-networking/uquic StreamGetter"
type StreamGetter = streamGetter

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_stream_sender_test.go github.com/refraction-networking/uquic StreamSender"
type StreamSender = streamSender

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_crypto_data_handler_test.go github.com/refraction-networking/uquic CryptoDataHandler"
type CryptoDataHandler = cryptoDataHandler

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_frame_source_test.go github.com/refraction-networking/uquic FrameSource"
type FrameSource = frameSource

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_ack_frame_source_test.go github.com/refraction-networking/uquic AckFrameSource"
type AckFrameSource = ackFrameSource

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_stream_manager_test.go github.com/refraction-networking/uquic StreamManager"
type StreamManager = streamManager

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_sealing_manager_test.go github.com/refraction-networking/uquic SealingManager"
type SealingManager = sealingManager

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_unpacker_test.go github.com/refraction-networking/uquic Unpacker"
type Unpacker = unpacker

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_packer_test.go github.com/refraction-networking/uquic Packer"
type Packer = packer

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_mtu_discoverer_test.go github.com/refraction-networking/uquic MTUDiscoverer"
type MTUDiscoverer = mtuDiscoverer

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_conn_runner_test.go github.com/refraction-networking/uquic ConnRunner"
type ConnRunner = connRunner

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_quic_conn_test.go github.com/refraction-networking/uquic QUICConn"
type QUICConn = quicConn

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_packet_handler_test.go github.com/refraction-networking/uquic PacketHandler"
type PacketHandler = packetHandler

//go:generate sh -c "go run go.uber.org/mock/mockgen -build_flags=\"-tags=gomock\" -package quic -self_package github.com/refraction-networking/uquic -destination mock_packet_handler_manager_test.go github.com/refraction-networking/uquic PacketHandlerManager"
type PacketHandlerManager = packetHandlerManager

// Need to use source mode for the batchConn, since reflect mode follows type aliases.
// See https://github.com/golang/mock/issues/244 for details.
//
//go:generate sh -c "go run go.uber.org/mock/mockgen -package quic -self_package github.com/refraction-networking/uquic -source sys_conn_oob.go -destination mock_batch_conn_test.go -mock_names batchConn=MockBatchConn"

//go:generate sh -c "go run go.uber.org/mock/mockgen -package quic -self_package github.com/refraction-networking/uquic -self_package github.com/refraction-networking/uquic -destination mock_token_store_test.go github.com/refraction-networking/uquic TokenStore"
//go:generate sh -c "go run go.uber.org/mock/mockgen -package quic -self_package github.com/refraction-networking/uquic -self_package github.com/refraction-networking/uquic -destination mock_packetconn_test.go net PacketConn"
