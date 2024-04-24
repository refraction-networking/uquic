// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/refraction-networking/uquic (interfaces: ReceiveStreamI)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package quic -self_package github.com/quic-go/quic-go -destination mock_receive_stream_internal_test.go github.com/quic-go/quic-go ReceiveStreamI
//

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"
	time "time"

	gomock "go.uber.org/mock/gomock"
	protocol "github.com/refraction-networking/uquic/internal/protocol"
	qerr "github.com/refraction-networking/uquic/internal/qerr"
	wire "github.com/refraction-networking/uquic/internal/wire"
)

// MockReceiveStreamI is a mock of ReceiveStreamI interface.
type MockReceiveStreamI struct {
	ctrl     *gomock.Controller
	recorder *MockReceiveStreamIMockRecorder
}

// MockReceiveStreamIMockRecorder is the mock recorder for MockReceiveStreamI.
type MockReceiveStreamIMockRecorder struct {
	mock *MockReceiveStreamI
}

// NewMockReceiveStreamI creates a new mock instance.
func NewMockReceiveStreamI(ctrl *gomock.Controller) *MockReceiveStreamI {
	mock := &MockReceiveStreamI{ctrl: ctrl}
	mock.recorder = &MockReceiveStreamIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockReceiveStreamI) EXPECT() *MockReceiveStreamIMockRecorder {
	return m.recorder
}

// CancelRead mocks base method.
func (m *MockReceiveStreamI) CancelRead(arg0 qerr.StreamErrorCode) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CancelRead", arg0)
}

// CancelRead indicates an expected call of CancelRead.
func (mr *MockReceiveStreamIMockRecorder) CancelRead(arg0 any) *MockReceiveStreamICancelReadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CancelRead", reflect.TypeOf((*MockReceiveStreamI)(nil).CancelRead), arg0)
	return &MockReceiveStreamICancelReadCall{Call: call}
}

// MockReceiveStreamICancelReadCall wrap *gomock.Call
type MockReceiveStreamICancelReadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamICancelReadCall) Return() *MockReceiveStreamICancelReadCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamICancelReadCall) Do(f func(qerr.StreamErrorCode)) *MockReceiveStreamICancelReadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamICancelReadCall) DoAndReturn(f func(qerr.StreamErrorCode)) *MockReceiveStreamICancelReadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Read mocks base method.
func (m *MockReceiveStreamI) Read(arg0 []byte) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Read", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Read indicates an expected call of Read.
func (mr *MockReceiveStreamIMockRecorder) Read(arg0 any) *MockReceiveStreamIReadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*MockReceiveStreamI)(nil).Read), arg0)
	return &MockReceiveStreamIReadCall{Call: call}
}

// MockReceiveStreamIReadCall wrap *gomock.Call
type MockReceiveStreamIReadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamIReadCall) Return(arg0 int, arg1 error) *MockReceiveStreamIReadCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamIReadCall) Do(f func([]byte) (int, error)) *MockReceiveStreamIReadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamIReadCall) DoAndReturn(f func([]byte) (int, error)) *MockReceiveStreamIReadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SetReadDeadline mocks base method.
func (m *MockReceiveStreamI) SetReadDeadline(arg0 time.Time) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetReadDeadline", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetReadDeadline indicates an expected call of SetReadDeadline.
func (mr *MockReceiveStreamIMockRecorder) SetReadDeadline(arg0 any) *MockReceiveStreamISetReadDeadlineCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetReadDeadline", reflect.TypeOf((*MockReceiveStreamI)(nil).SetReadDeadline), arg0)
	return &MockReceiveStreamISetReadDeadlineCall{Call: call}
}

// MockReceiveStreamISetReadDeadlineCall wrap *gomock.Call
type MockReceiveStreamISetReadDeadlineCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamISetReadDeadlineCall) Return(arg0 error) *MockReceiveStreamISetReadDeadlineCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamISetReadDeadlineCall) Do(f func(time.Time) error) *MockReceiveStreamISetReadDeadlineCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamISetReadDeadlineCall) DoAndReturn(f func(time.Time) error) *MockReceiveStreamISetReadDeadlineCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// StreamID mocks base method.
func (m *MockReceiveStreamI) StreamID() protocol.StreamID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StreamID")
	ret0, _ := ret[0].(protocol.StreamID)
	return ret0
}

// StreamID indicates an expected call of StreamID.
func (mr *MockReceiveStreamIMockRecorder) StreamID() *MockReceiveStreamIStreamIDCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StreamID", reflect.TypeOf((*MockReceiveStreamI)(nil).StreamID))
	return &MockReceiveStreamIStreamIDCall{Call: call}
}

// MockReceiveStreamIStreamIDCall wrap *gomock.Call
type MockReceiveStreamIStreamIDCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamIStreamIDCall) Return(arg0 protocol.StreamID) *MockReceiveStreamIStreamIDCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamIStreamIDCall) Do(f func() protocol.StreamID) *MockReceiveStreamIStreamIDCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamIStreamIDCall) DoAndReturn(f func() protocol.StreamID) *MockReceiveStreamIStreamIDCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// closeForShutdown mocks base method.
func (m *MockReceiveStreamI) closeForShutdown(arg0 error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "closeForShutdown", arg0)
}

// closeForShutdown indicates an expected call of closeForShutdown.
func (mr *MockReceiveStreamIMockRecorder) closeForShutdown(arg0 any) *MockReceiveStreamIcloseForShutdownCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "closeForShutdown", reflect.TypeOf((*MockReceiveStreamI)(nil).closeForShutdown), arg0)
	return &MockReceiveStreamIcloseForShutdownCall{Call: call}
}

// MockReceiveStreamIcloseForShutdownCall wrap *gomock.Call
type MockReceiveStreamIcloseForShutdownCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamIcloseForShutdownCall) Return() *MockReceiveStreamIcloseForShutdownCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamIcloseForShutdownCall) Do(f func(error)) *MockReceiveStreamIcloseForShutdownCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamIcloseForShutdownCall) DoAndReturn(f func(error)) *MockReceiveStreamIcloseForShutdownCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// getWindowUpdate mocks base method.
func (m *MockReceiveStreamI) getWindowUpdate() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "getWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// getWindowUpdate indicates an expected call of getWindowUpdate.
func (mr *MockReceiveStreamIMockRecorder) getWindowUpdate() *MockReceiveStreamIgetWindowUpdateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getWindowUpdate", reflect.TypeOf((*MockReceiveStreamI)(nil).getWindowUpdate))
	return &MockReceiveStreamIgetWindowUpdateCall{Call: call}
}

// MockReceiveStreamIgetWindowUpdateCall wrap *gomock.Call
type MockReceiveStreamIgetWindowUpdateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamIgetWindowUpdateCall) Return(arg0 protocol.ByteCount) *MockReceiveStreamIgetWindowUpdateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamIgetWindowUpdateCall) Do(f func() protocol.ByteCount) *MockReceiveStreamIgetWindowUpdateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamIgetWindowUpdateCall) DoAndReturn(f func() protocol.ByteCount) *MockReceiveStreamIgetWindowUpdateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// handleResetStreamFrame mocks base method.
func (m *MockReceiveStreamI) handleResetStreamFrame(arg0 *wire.ResetStreamFrame) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "handleResetStreamFrame", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// handleResetStreamFrame indicates an expected call of handleResetStreamFrame.
func (mr *MockReceiveStreamIMockRecorder) handleResetStreamFrame(arg0 any) *MockReceiveStreamIhandleResetStreamFrameCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "handleResetStreamFrame", reflect.TypeOf((*MockReceiveStreamI)(nil).handleResetStreamFrame), arg0)
	return &MockReceiveStreamIhandleResetStreamFrameCall{Call: call}
}

// MockReceiveStreamIhandleResetStreamFrameCall wrap *gomock.Call
type MockReceiveStreamIhandleResetStreamFrameCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamIhandleResetStreamFrameCall) Return(arg0 error) *MockReceiveStreamIhandleResetStreamFrameCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamIhandleResetStreamFrameCall) Do(f func(*wire.ResetStreamFrame) error) *MockReceiveStreamIhandleResetStreamFrameCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamIhandleResetStreamFrameCall) DoAndReturn(f func(*wire.ResetStreamFrame) error) *MockReceiveStreamIhandleResetStreamFrameCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// handleStreamFrame mocks base method.
func (m *MockReceiveStreamI) handleStreamFrame(arg0 *wire.StreamFrame) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "handleStreamFrame", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// handleStreamFrame indicates an expected call of handleStreamFrame.
func (mr *MockReceiveStreamIMockRecorder) handleStreamFrame(arg0 any) *MockReceiveStreamIhandleStreamFrameCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "handleStreamFrame", reflect.TypeOf((*MockReceiveStreamI)(nil).handleStreamFrame), arg0)
	return &MockReceiveStreamIhandleStreamFrameCall{Call: call}
}

// MockReceiveStreamIhandleStreamFrameCall wrap *gomock.Call
type MockReceiveStreamIhandleStreamFrameCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockReceiveStreamIhandleStreamFrameCall) Return(arg0 error) *MockReceiveStreamIhandleStreamFrameCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockReceiveStreamIhandleStreamFrameCall) Do(f func(*wire.StreamFrame) error) *MockReceiveStreamIhandleStreamFrameCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockReceiveStreamIhandleStreamFrameCall) DoAndReturn(f func(*wire.StreamFrame) error) *MockReceiveStreamIhandleStreamFrameCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
