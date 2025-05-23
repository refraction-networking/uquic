// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/refraction-networking/uquic (interfaces: PacketHandlerManager)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package quic -self_package github.com/quic-go/quic-go -destination mock_packet_handler_manager_test.go github.com/quic-go/quic-go PacketHandlerManager
//

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
	protocol "github.com/refraction-networking/uquic/internal/protocol"
)

// MockPacketHandlerManager is a mock of PacketHandlerManager interface.
type MockPacketHandlerManager struct {
	ctrl     *gomock.Controller
	recorder *MockPacketHandlerManagerMockRecorder
	isgomock struct{}
}

// MockPacketHandlerManagerMockRecorder is the mock recorder for MockPacketHandlerManager.
type MockPacketHandlerManagerMockRecorder struct {
	mock *MockPacketHandlerManager
}

// NewMockPacketHandlerManager creates a new mock instance.
func NewMockPacketHandlerManager(ctrl *gomock.Controller) *MockPacketHandlerManager {
	mock := &MockPacketHandlerManager{ctrl: ctrl}
	mock.recorder = &MockPacketHandlerManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPacketHandlerManager) EXPECT() *MockPacketHandlerManagerMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockPacketHandlerManager) Add(arg0 protocol.ConnectionID, arg1 packetHandler) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", arg0, arg1)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockPacketHandlerManagerMockRecorder) Add(arg0, arg1 any) *MockPacketHandlerManagerAddCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockPacketHandlerManager)(nil).Add), arg0, arg1)
	return &MockPacketHandlerManagerAddCall{Call: call}
}

// MockPacketHandlerManagerAddCall wrap *gomock.Call
type MockPacketHandlerManagerAddCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerAddCall) Return(arg0 bool) *MockPacketHandlerManagerAddCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerAddCall) Do(f func(protocol.ConnectionID, packetHandler) bool) *MockPacketHandlerManagerAddCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerAddCall) DoAndReturn(f func(protocol.ConnectionID, packetHandler) bool) *MockPacketHandlerManagerAddCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AddResetToken mocks base method.
func (m *MockPacketHandlerManager) AddResetToken(arg0 protocol.StatelessResetToken, arg1 packetHandler) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddResetToken", arg0, arg1)
}

// AddResetToken indicates an expected call of AddResetToken.
func (mr *MockPacketHandlerManagerMockRecorder) AddResetToken(arg0, arg1 any) *MockPacketHandlerManagerAddResetTokenCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddResetToken", reflect.TypeOf((*MockPacketHandlerManager)(nil).AddResetToken), arg0, arg1)
	return &MockPacketHandlerManagerAddResetTokenCall{Call: call}
}

// MockPacketHandlerManagerAddResetTokenCall wrap *gomock.Call
type MockPacketHandlerManagerAddResetTokenCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerAddResetTokenCall) Return() *MockPacketHandlerManagerAddResetTokenCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerAddResetTokenCall) Do(f func(protocol.StatelessResetToken, packetHandler)) *MockPacketHandlerManagerAddResetTokenCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerAddResetTokenCall) DoAndReturn(f func(protocol.StatelessResetToken, packetHandler)) *MockPacketHandlerManagerAddResetTokenCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// AddWithConnID mocks base method.
func (m *MockPacketHandlerManager) AddWithConnID(destConnID, newConnID protocol.ConnectionID, h packetHandler) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddWithConnID", destConnID, newConnID, h)
	ret0, _ := ret[0].(bool)
	return ret0
}

// AddWithConnID indicates an expected call of AddWithConnID.
func (mr *MockPacketHandlerManagerMockRecorder) AddWithConnID(destConnID, newConnID, h any) *MockPacketHandlerManagerAddWithConnIDCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddWithConnID", reflect.TypeOf((*MockPacketHandlerManager)(nil).AddWithConnID), destConnID, newConnID, h)
	return &MockPacketHandlerManagerAddWithConnIDCall{Call: call}
}

// MockPacketHandlerManagerAddWithConnIDCall wrap *gomock.Call
type MockPacketHandlerManagerAddWithConnIDCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerAddWithConnIDCall) Return(arg0 bool) *MockPacketHandlerManagerAddWithConnIDCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerAddWithConnIDCall) Do(f func(protocol.ConnectionID, protocol.ConnectionID, packetHandler) bool) *MockPacketHandlerManagerAddWithConnIDCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerAddWithConnIDCall) DoAndReturn(f func(protocol.ConnectionID, protocol.ConnectionID, packetHandler) bool) *MockPacketHandlerManagerAddWithConnIDCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Close mocks base method.
func (m *MockPacketHandlerManager) Close(arg0 error) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close", arg0)
}

// Close indicates an expected call of Close.
func (mr *MockPacketHandlerManagerMockRecorder) Close(arg0 any) *MockPacketHandlerManagerCloseCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockPacketHandlerManager)(nil).Close), arg0)
	return &MockPacketHandlerManagerCloseCall{Call: call}
}

// MockPacketHandlerManagerCloseCall wrap *gomock.Call
type MockPacketHandlerManagerCloseCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerCloseCall) Return() *MockPacketHandlerManagerCloseCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerCloseCall) Do(f func(error)) *MockPacketHandlerManagerCloseCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerCloseCall) DoAndReturn(f func(error)) *MockPacketHandlerManagerCloseCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Get mocks base method.
func (m *MockPacketHandlerManager) Get(arg0 protocol.ConnectionID) (packetHandler, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0)
	ret0, _ := ret[0].(packetHandler)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockPacketHandlerManagerMockRecorder) Get(arg0 any) *MockPacketHandlerManagerGetCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockPacketHandlerManager)(nil).Get), arg0)
	return &MockPacketHandlerManagerGetCall{Call: call}
}

// MockPacketHandlerManagerGetCall wrap *gomock.Call
type MockPacketHandlerManagerGetCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerGetCall) Return(arg0 packetHandler, arg1 bool) *MockPacketHandlerManagerGetCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerGetCall) Do(f func(protocol.ConnectionID) (packetHandler, bool)) *MockPacketHandlerManagerGetCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerGetCall) DoAndReturn(f func(protocol.ConnectionID) (packetHandler, bool)) *MockPacketHandlerManagerGetCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetByResetToken mocks base method.
func (m *MockPacketHandlerManager) GetByResetToken(arg0 protocol.StatelessResetToken) (packetHandler, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetByResetToken", arg0)
	ret0, _ := ret[0].(packetHandler)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// GetByResetToken indicates an expected call of GetByResetToken.
func (mr *MockPacketHandlerManagerMockRecorder) GetByResetToken(arg0 any) *MockPacketHandlerManagerGetByResetTokenCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByResetToken", reflect.TypeOf((*MockPacketHandlerManager)(nil).GetByResetToken), arg0)
	return &MockPacketHandlerManagerGetByResetTokenCall{Call: call}
}

// MockPacketHandlerManagerGetByResetTokenCall wrap *gomock.Call
type MockPacketHandlerManagerGetByResetTokenCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerGetByResetTokenCall) Return(arg0 packetHandler, arg1 bool) *MockPacketHandlerManagerGetByResetTokenCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerGetByResetTokenCall) Do(f func(protocol.StatelessResetToken) (packetHandler, bool)) *MockPacketHandlerManagerGetByResetTokenCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerGetByResetTokenCall) DoAndReturn(f func(protocol.StatelessResetToken) (packetHandler, bool)) *MockPacketHandlerManagerGetByResetTokenCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Remove mocks base method.
func (m *MockPacketHandlerManager) Remove(arg0 protocol.ConnectionID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Remove", arg0)
}

// Remove indicates an expected call of Remove.
func (mr *MockPacketHandlerManagerMockRecorder) Remove(arg0 any) *MockPacketHandlerManagerRemoveCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockPacketHandlerManager)(nil).Remove), arg0)
	return &MockPacketHandlerManagerRemoveCall{Call: call}
}

// MockPacketHandlerManagerRemoveCall wrap *gomock.Call
type MockPacketHandlerManagerRemoveCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerRemoveCall) Return() *MockPacketHandlerManagerRemoveCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerRemoveCall) Do(f func(protocol.ConnectionID)) *MockPacketHandlerManagerRemoveCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerRemoveCall) DoAndReturn(f func(protocol.ConnectionID)) *MockPacketHandlerManagerRemoveCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// RemoveResetToken mocks base method.
func (m *MockPacketHandlerManager) RemoveResetToken(arg0 protocol.StatelessResetToken) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "RemoveResetToken", arg0)
}

// RemoveResetToken indicates an expected call of RemoveResetToken.
func (mr *MockPacketHandlerManagerMockRecorder) RemoveResetToken(arg0 any) *MockPacketHandlerManagerRemoveResetTokenCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoveResetToken", reflect.TypeOf((*MockPacketHandlerManager)(nil).RemoveResetToken), arg0)
	return &MockPacketHandlerManagerRemoveResetTokenCall{Call: call}
}

// MockPacketHandlerManagerRemoveResetTokenCall wrap *gomock.Call
type MockPacketHandlerManagerRemoveResetTokenCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerRemoveResetTokenCall) Return() *MockPacketHandlerManagerRemoveResetTokenCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerRemoveResetTokenCall) Do(f func(protocol.StatelessResetToken)) *MockPacketHandlerManagerRemoveResetTokenCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerRemoveResetTokenCall) DoAndReturn(f func(protocol.StatelessResetToken)) *MockPacketHandlerManagerRemoveResetTokenCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// ReplaceWithClosed mocks base method.
func (m *MockPacketHandlerManager) ReplaceWithClosed(arg0 []protocol.ConnectionID, arg1 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReplaceWithClosed", arg0, arg1)
}

// ReplaceWithClosed indicates an expected call of ReplaceWithClosed.
func (mr *MockPacketHandlerManagerMockRecorder) ReplaceWithClosed(arg0, arg1 any) *MockPacketHandlerManagerReplaceWithClosedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReplaceWithClosed", reflect.TypeOf((*MockPacketHandlerManager)(nil).ReplaceWithClosed), arg0, arg1)
	return &MockPacketHandlerManagerReplaceWithClosedCall{Call: call}
}

// MockPacketHandlerManagerReplaceWithClosedCall wrap *gomock.Call
type MockPacketHandlerManagerReplaceWithClosedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerReplaceWithClosedCall) Return() *MockPacketHandlerManagerReplaceWithClosedCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerReplaceWithClosedCall) Do(f func([]protocol.ConnectionID, []byte)) *MockPacketHandlerManagerReplaceWithClosedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerReplaceWithClosedCall) DoAndReturn(f func([]protocol.ConnectionID, []byte)) *MockPacketHandlerManagerReplaceWithClosedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Retire mocks base method.
func (m *MockPacketHandlerManager) Retire(arg0 protocol.ConnectionID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Retire", arg0)
}

// Retire indicates an expected call of Retire.
func (mr *MockPacketHandlerManagerMockRecorder) Retire(arg0 any) *MockPacketHandlerManagerRetireCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Retire", reflect.TypeOf((*MockPacketHandlerManager)(nil).Retire), arg0)
	return &MockPacketHandlerManagerRetireCall{Call: call}
}

// MockPacketHandlerManagerRetireCall wrap *gomock.Call
type MockPacketHandlerManagerRetireCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockPacketHandlerManagerRetireCall) Return() *MockPacketHandlerManagerRetireCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockPacketHandlerManagerRetireCall) Do(f func(protocol.ConnectionID)) *MockPacketHandlerManagerRetireCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockPacketHandlerManagerRetireCall) DoAndReturn(f func(protocol.ConnectionID)) *MockPacketHandlerManagerRetireCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
