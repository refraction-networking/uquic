// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/refraction-networking/uquic (interfaces: RawConn)
//
// Generated by this command:
//
//	mockgen -build_flags=-tags=gomock -package quic -self_package github.com/refraction-networking/uquic -destination mock_raw_conn_test.go github.com/refraction-networking/uquic RawConn
//
// Package quic is a generated GoMock package.
package quic

import (
	net "net"
	reflect "reflect"
	time "time"

	protocol "github.com/refraction-networking/uquic/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockRawConn is a mock of RawConn interface.
type MockRawConn struct {
	ctrl     *gomock.Controller
	recorder *MockRawConnMockRecorder
}

// MockRawConnMockRecorder is the mock recorder for MockRawConn.
type MockRawConnMockRecorder struct {
	mock *MockRawConn
}

// NewMockRawConn creates a new mock instance.
func NewMockRawConn(ctrl *gomock.Controller) *MockRawConn {
	mock := &MockRawConn{ctrl: ctrl}
	mock.recorder = &MockRawConnMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRawConn) EXPECT() *MockRawConnMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRawConn) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockRawConnMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRawConn)(nil).Close))
}

// LocalAddr mocks base method.
func (m *MockRawConn) LocalAddr() net.Addr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LocalAddr")
	ret0, _ := ret[0].(net.Addr)
	return ret0
}

// LocalAddr indicates an expected call of LocalAddr.
func (mr *MockRawConnMockRecorder) LocalAddr() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalAddr", reflect.TypeOf((*MockRawConn)(nil).LocalAddr))
}

// ReadPacket mocks base method.
func (m *MockRawConn) ReadPacket() (receivedPacket, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadPacket")
	ret0, _ := ret[0].(receivedPacket)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadPacket indicates an expected call of ReadPacket.
func (mr *MockRawConnMockRecorder) ReadPacket() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadPacket", reflect.TypeOf((*MockRawConn)(nil).ReadPacket))
}

// SetReadDeadline mocks base method.
func (m *MockRawConn) SetReadDeadline(arg0 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetReadDeadline", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetReadDeadline indicates an expected call of SetReadDeadline.
func (mr *MockRawConnMockRecorder) SetReadDeadline(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetReadDeadline", reflect.TypeOf((*MockRawConn)(nil).SetReadDeadline), arg0)
}

// WritePacket mocks base method.
func (m *MockRawConn) WritePacket(arg0 []byte, arg1 net.Addr, arg2 []byte, arg3 uint16, arg4 protocol.ECN) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WritePacket", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WritePacket indicates an expected call of WritePacket.
func (mr *MockRawConnMockRecorder) WritePacket(arg0, arg1, arg2, arg3, arg4 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WritePacket", reflect.TypeOf((*MockRawConn)(nil).WritePacket), arg0, arg1, arg2, arg3, arg4)
}

// capabilities mocks base method.
func (m *MockRawConn) capabilities() connCapabilities {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "capabilities")
	ret0, _ := ret[0].(connCapabilities)
	return ret0
}

// capabilities indicates an expected call of capabilities.
func (mr *MockRawConnMockRecorder) capabilities() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "capabilities", reflect.TypeOf((*MockRawConn)(nil).capabilities))
}
