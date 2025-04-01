// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/refraction-networking/uquic/internal/flowcontrol (interfaces: ConnectionFlowController)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package mocks -destination connection_flow_controller.go github.com/quic-go/quic-go/internal/flowcontrol ConnectionFlowController
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"
	time "time"

	gomock "go.uber.org/mock/gomock"
	protocol "github.com/refraction-networking/uquic/internal/protocol"
)

// MockConnectionFlowController is a mock of ConnectionFlowController interface.
type MockConnectionFlowController struct {
	ctrl     *gomock.Controller
	recorder *MockConnectionFlowControllerMockRecorder
	isgomock struct{}
}

// MockConnectionFlowControllerMockRecorder is the mock recorder for MockConnectionFlowController.
type MockConnectionFlowControllerMockRecorder struct {
	mock *MockConnectionFlowController
}

// NewMockConnectionFlowController creates a new mock instance.
func NewMockConnectionFlowController(ctrl *gomock.Controller) *MockConnectionFlowController {
	mock := &MockConnectionFlowController{ctrl: ctrl}
	mock.recorder = &MockConnectionFlowControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConnectionFlowController) EXPECT() *MockConnectionFlowControllerMockRecorder {
	return m.recorder
}

// AddBytesRead mocks base method.
func (m *MockConnectionFlowController) AddBytesRead(arg0 protocol.ByteCount) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddBytesRead", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// AddBytesRead indicates an expected call of AddBytesRead.
func (mr *MockConnectionFlowControllerMockRecorder) AddBytesRead(arg0 any) *MockConnectionFlowControllerAddBytesReadCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBytesRead", reflect.TypeOf((*MockConnectionFlowController)(nil).AddBytesRead), arg0)
	return &MockConnectionFlowControllerAddBytesReadCall{Call: call}
}

// MockConnectionFlowControllerAddBytesReadCall wrap *gomock.Call
type MockConnectionFlowControllerAddBytesReadCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnectionFlowControllerAddBytesReadCall) Return(hasWindowUpdate bool) *MockConnectionFlowControllerAddBytesReadCall {
	c.Call = c.Call.Return(hasWindowUpdate)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnectionFlowControllerAddBytesReadCall) Do(f func(protocol.ByteCount) bool) *MockConnectionFlowControllerAddBytesReadCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnectionFlowControllerAddBytesReadCall) DoAndReturn(f func(protocol.ByteCount) bool) *MockConnectionFlowControllerAddBytesReadCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AddBytesSent mocks base method.
func (m *MockConnectionFlowController) AddBytesSent(arg0 protocol.ByteCount) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddBytesSent", arg0)
}

// AddBytesSent indicates an expected call of AddBytesSent.
func (mr *MockConnectionFlowControllerMockRecorder) AddBytesSent(arg0 any) *MockConnectionFlowControllerAddBytesSentCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddBytesSent", reflect.TypeOf((*MockConnectionFlowController)(nil).AddBytesSent), arg0)
	return &MockConnectionFlowControllerAddBytesSentCall{Call: call}
}

// MockConnectionFlowControllerAddBytesSentCall wrap *gomock.Call
type MockConnectionFlowControllerAddBytesSentCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnectionFlowControllerAddBytesSentCall) Return() *MockConnectionFlowControllerAddBytesSentCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnectionFlowControllerAddBytesSentCall) Do(f func(protocol.ByteCount)) *MockConnectionFlowControllerAddBytesSentCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnectionFlowControllerAddBytesSentCall) DoAndReturn(f func(protocol.ByteCount)) *MockConnectionFlowControllerAddBytesSentCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetWindowUpdate mocks base method.
func (m *MockConnectionFlowController) GetWindowUpdate(arg0 time.Time) protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetWindowUpdate", arg0)
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// GetWindowUpdate indicates an expected call of GetWindowUpdate.
func (mr *MockConnectionFlowControllerMockRecorder) GetWindowUpdate(arg0 any) *MockConnectionFlowControllerGetWindowUpdateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetWindowUpdate", reflect.TypeOf((*MockConnectionFlowController)(nil).GetWindowUpdate), arg0)
	return &MockConnectionFlowControllerGetWindowUpdateCall{Call: call}
}

// MockConnectionFlowControllerGetWindowUpdateCall wrap *gomock.Call
type MockConnectionFlowControllerGetWindowUpdateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnectionFlowControllerGetWindowUpdateCall) Return(arg0 protocol.ByteCount) *MockConnectionFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnectionFlowControllerGetWindowUpdateCall) Do(f func(time.Time) protocol.ByteCount) *MockConnectionFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnectionFlowControllerGetWindowUpdateCall) DoAndReturn(f func(time.Time) protocol.ByteCount) *MockConnectionFlowControllerGetWindowUpdateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// IsNewlyBlocked mocks base method.
func (m *MockConnectionFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsNewlyBlocked")
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(protocol.ByteCount)
	return ret0, ret1
}

// IsNewlyBlocked indicates an expected call of IsNewlyBlocked.
func (mr *MockConnectionFlowControllerMockRecorder) IsNewlyBlocked() *MockConnectionFlowControllerIsNewlyBlockedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsNewlyBlocked", reflect.TypeOf((*MockConnectionFlowController)(nil).IsNewlyBlocked))
	return &MockConnectionFlowControllerIsNewlyBlockedCall{Call: call}
}

// MockConnectionFlowControllerIsNewlyBlockedCall wrap *gomock.Call
type MockConnectionFlowControllerIsNewlyBlockedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnectionFlowControllerIsNewlyBlockedCall) Return(arg0 bool, arg1 protocol.ByteCount) *MockConnectionFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnectionFlowControllerIsNewlyBlockedCall) Do(f func() (bool, protocol.ByteCount)) *MockConnectionFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnectionFlowControllerIsNewlyBlockedCall) DoAndReturn(f func() (bool, protocol.ByteCount)) *MockConnectionFlowControllerIsNewlyBlockedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Reset mocks base method.
func (m *MockConnectionFlowController) Reset() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Reset")
	ret0, _ := ret[0].(error)
	return ret0
}

// Reset indicates an expected call of Reset.
func (mr *MockConnectionFlowControllerMockRecorder) Reset() *MockConnectionFlowControllerResetCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reset", reflect.TypeOf((*MockConnectionFlowController)(nil).Reset))
	return &MockConnectionFlowControllerResetCall{Call: call}
}

// MockConnectionFlowControllerResetCall wrap *gomock.Call
type MockConnectionFlowControllerResetCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnectionFlowControllerResetCall) Return(arg0 error) *MockConnectionFlowControllerResetCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnectionFlowControllerResetCall) Do(f func() error) *MockConnectionFlowControllerResetCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnectionFlowControllerResetCall) DoAndReturn(f func() error) *MockConnectionFlowControllerResetCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// SendWindowSize mocks base method.
func (m *MockConnectionFlowController) SendWindowSize() protocol.ByteCount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendWindowSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// SendWindowSize indicates an expected call of SendWindowSize.
func (mr *MockConnectionFlowControllerMockRecorder) SendWindowSize() *MockConnectionFlowControllerSendWindowSizeCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendWindowSize", reflect.TypeOf((*MockConnectionFlowController)(nil).SendWindowSize))
	return &MockConnectionFlowControllerSendWindowSizeCall{Call: call}
}

// MockConnectionFlowControllerSendWindowSizeCall wrap *gomock.Call
type MockConnectionFlowControllerSendWindowSizeCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnectionFlowControllerSendWindowSizeCall) Return(arg0 protocol.ByteCount) *MockConnectionFlowControllerSendWindowSizeCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnectionFlowControllerSendWindowSizeCall) Do(f func() protocol.ByteCount) *MockConnectionFlowControllerSendWindowSizeCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnectionFlowControllerSendWindowSizeCall) DoAndReturn(f func() protocol.ByteCount) *MockConnectionFlowControllerSendWindowSizeCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// UpdateSendWindow mocks base method.
func (m *MockConnectionFlowController) UpdateSendWindow(arg0 protocol.ByteCount) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSendWindow", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// UpdateSendWindow indicates an expected call of UpdateSendWindow.
func (mr *MockConnectionFlowControllerMockRecorder) UpdateSendWindow(arg0 any) *MockConnectionFlowControllerUpdateSendWindowCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSendWindow", reflect.TypeOf((*MockConnectionFlowController)(nil).UpdateSendWindow), arg0)
	return &MockConnectionFlowControllerUpdateSendWindowCall{Call: call}
}

// MockConnectionFlowControllerUpdateSendWindowCall wrap *gomock.Call
type MockConnectionFlowControllerUpdateSendWindowCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockConnectionFlowControllerUpdateSendWindowCall) Return(updated bool) *MockConnectionFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.Return(updated)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockConnectionFlowControllerUpdateSendWindowCall) Do(f func(protocol.ByteCount) bool) *MockConnectionFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockConnectionFlowControllerUpdateSendWindowCall) DoAndReturn(f func(protocol.ByteCount) bool) *MockConnectionFlowControllerUpdateSendWindowCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
