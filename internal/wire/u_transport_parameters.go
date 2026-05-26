package wire

// [uQUIC] This file adds uQUIC-specific extensions to TransportParameters.

import (
	"time"

	"github.com/refraction-networking/uquic/internal/protocol"
	tls "github.com/refraction-networking/utls"
)

// PopulateFromUQUIC sets TransportParameters fields from a uTLS TransportParameters slice
// (from QUICTransportParametersExtension) and stores the marshaled bytes as ClientOverride
// so that Marshal/MarshalForSessionTicket reproduce the exact user-specified encoding.
func (tp *TransportParameters) PopulateFromUQUIC(quicparams tls.TransportParameters) {
	for pIdx, param := range quicparams {
		switch param.ID() {
		case uint64(maxIdleTimeoutParameterID):
			tp.MaxIdleTimeout = time.Duration(param.(tls.MaxIdleTimeout)) * time.Millisecond
		case uint64(initialMaxDataParameterID):
			tp.InitialMaxData = protocol.ByteCount(param.(tls.InitialMaxData))
		case uint64(initialMaxStreamDataBidiLocalParameterID):
			tp.InitialMaxStreamDataBidiLocal = protocol.ByteCount(param.(tls.InitialMaxStreamDataBidiLocal))
		case uint64(initialMaxStreamDataBidiRemoteParameterID):
			tp.InitialMaxStreamDataBidiRemote = protocol.ByteCount(param.(tls.InitialMaxStreamDataBidiRemote))
		case uint64(initialMaxStreamDataUniParameterID):
			tp.InitialMaxStreamDataUni = protocol.ByteCount(param.(tls.InitialMaxStreamDataUni))
		case uint64(initialMaxStreamsBidiParameterID):
			tp.MaxBidiStreamNum = protocol.StreamNum(param.(tls.InitialMaxStreamsBidi))
		case uint64(initialMaxStreamsUniParameterID):
			tp.MaxUniStreamNum = protocol.StreamNum(param.(tls.InitialMaxStreamsUni))
		case uint64(maxAckDelayParameterID):
			tp.MaxAckDelay = time.Duration(param.(tls.MaxAckDelay)) * time.Millisecond
		case uint64(disableActiveMigrationParameterID):
			tp.DisableActiveMigration = true
		case uint64(activeConnectionIDLimitParameterID):
			tp.ActiveConnectionIDLimit = uint64(param.(tls.ActiveConnectionIDLimit))
		case uint64(initialSourceConnectionIDParameterID):
			srcConnIDOverride, ok := param.(tls.InitialSourceConnectionID)
			if ok {
				if len(srcConnIDOverride) > 0 {
					// user specified a source connection ID — use it
					tp.InitialSourceConnectionID = protocol.ParseConnectionID(srcConnIDOverride)
				} else {
					// zero-length: populate the param with the actual srcConnID bytes so the
					// wire encoding contains the correct connection ID
					quicparams[pIdx] = tls.InitialSourceConnectionID(tp.InitialSourceConnectionID.Bytes())
				}
			}
		case uint64(maxDatagramFrameSizeParameterID):
			tp.MaxDatagramFrameSize = protocol.ByteCount(param.(tls.MaxDatagramFrameSize))
		default:
			// ignore unknown parameters
			continue
		}
	}

	// Store the marshaled bytes as the override so Marshal reproduces the exact fingerprint
	tp.ClientOverride = quicparams.Marshal()
}
