/*
 * Copyright 2018 The ThunderDB Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kayak

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/thunderdb/ThunderDB/crypto/hash"
	"github.com/thunderdb/ThunderDB/crypto/signature"
)

// Log entries are replicated to all members of the Raft cluster
// and form the heart of the replicated state machine.
type Log struct {
	// Index holds the index of the log entry.
	Index uint64

	// Term holds the election term of the log entry.
	Term uint64

	// Data holds the log entry's type-specific data.
	Data []byte

	// LastHash is log entry hash
	LastHash *hash.Hash

	// Hash is current log entry hash
	Hash hash.Hash
}

// ReHash update Hash with generated hash.
func (l *Log) ReHash() {
	l.Hash.SetBytes(hash.DoubleHashB(l.getBytes()))
}

// VerifyHash validates hash field.
func (l *Log) VerifyHash() bool {
	h := hash.DoubleHashH(l.getBytes())
	return h.IsEqual(&l.Hash)
}

func (l *Log) getBytes() []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, &l.Index)
	binary.Write(buf, binary.LittleEndian, &l.Term)
	buf.Write(l.Data)
	if l.LastHash != nil {
		buf.Write(l.LastHash.CloneBytes())
	}

	return buf.Bytes()
}

// LogStore is used to provide an interface for storing
// and retrieving logs in a durable fashion.
type LogStore interface {
	// FirstIndex returns the first index written. 0 for no entries.
	FirstIndex() (uint64, error)

	// LastIndex returns the last index written. 0 for no entries.
	LastIndex() (uint64, error)

	// GetLog gets a log entry at a given index.
	GetLog(index uint64, l *Log) error

	// StoreLog stores a log entry.
	StoreLog(l *Log) error

	// StoreLogs stores multiple log entries.
	StoreLogs(logs []*Log) error

	// DeleteRange deletes a range of log entries. The range is inclusive.
	DeleteRange(min, max uint64) error
}

// StableStore is used to provide stable storage
// of key configurations to ensure safety.
type StableStore interface {
	Set(key []byte, val []byte) error

	// Get returns the value for key, or an empty byte slice if key was not found.
	Get(key []byte) ([]byte, error)

	SetUint64(key []byte, val uint64) error

	// GetUint64 returns the uint64 value for key, or 0 if key was not found.
	GetUint64(key []byte) (uint64, error)
}

// ServerID is a unique string identifying a server for all time.
type ServerID string

// ServerAddress is a network address for a server that a transport can contact.
type ServerAddress string

// ServerRole define the role of node to be leader/coordinator in peer set
type ServerRole int

// Note: Don't renumber these, since the numbers are written into the log.
const (
	// Peer is a server whose vote is counted in elections and whose match index
	// is used in advancing the leader's commit index.
	Leader ServerRole = iota
	// Learner is a server that receives log entries but is not considered for
	// elections or commitment purposes.
	Follower
)

func (s ServerRole) String() string {
	switch s {
	case Leader:
		return "Leader"
	case Follower:
		return "Follower"
	}
	return "Unknown"
}

// Server tracks the information about a single server in a configuration.
type Server struct {
	// Suffrage determines whether the server gets a vote.
	Role ServerRole
	// ID is a unique string identifying this server for all time.
	ID ServerID
	// Address is its network address that a transport can contact.
	Address ServerAddress
	// Public key
	PubKey *signature.PublicKey
}

func (s *Server) String() string {
	return fmt.Sprintf("Server id:%s role:%s address:%s pubKey:%s",
		s.ID, s.Role, s.Address,
		base64.StdEncoding.EncodeToString(s.PubKey.Serialize()))
}

// Serialize payload to bytes
func (s *Server) Serialize() []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, s.Role)
	binary.Write(buffer, binary.LittleEndian, s.ID)
	binary.Write(buffer, binary.LittleEndian, s.Address)
	buffer.Write(s.PubKey.Serialize())

	return buffer.Bytes()
}

// Peers defines peer configuration.
type Peers struct {
	Term      uint64
	Leader    *Server
	Servers   []*Server
	PubKey    *signature.PublicKey
	Signature *signature.Signature
}

// Clone makes a deep copy of a Peers.
func (c *Peers) Clone() (copy Peers) {
	copy.Term = c.Term
	copy.Leader = c.Leader
	copy.Servers = append(copy.Servers, c.Servers...)
	copy.Signature = c.Signature
	return
}

func (c *Peers) getBytes() []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, c.Term)
	binary.Write(buffer, binary.LittleEndian, c.Leader.Serialize())
	for _, s := range c.Servers {
		binary.Write(buffer, binary.LittleEndian, s.Serialize())
	}
	return buffer.Bytes()
}

// Sign generates signature
func (c *Peers) Sign(signer *signature.PrivateKey) error {
	sig, err := signer.Sign(c.getBytes())

	if err != nil {
		return fmt.Errorf("sign peer configuration failed: %s", err.Error())
	}

	c.Signature = sig

	return nil
}

// Verify verify signature
func (c *Peers) Verify() bool {
	return c.Signature.Verify(c.getBytes(), c.PubKey)
}

func (c *Peers) String() string {
	return fmt.Sprintf("Peers term:%v nodesCnt:%v leader:%s signature:%s",
		c.Term, len(c.Servers), c.Leader.ID,
		base64.StdEncoding.EncodeToString(c.Signature.Serialize()))
}

// Config defines minimal configuration fields for consensus runner.
type Config struct {
	// RootDir is the root dir for runtime
	RootDir string

	// LocalID is the unique ID for this server across all time.
	LocalID ServerID

	// Runner defines the runner type
	Runner Runner

	// Dialer defines the dialer type
	Dialer Dialer

	// Logger is the logger
	Logger log.Logger
}

// Dialer adapter for abstraction.
type Dialer interface {
	// Dial connects to the destination server.
	Dial(serverID ServerID) (net.Conn, error)

	// DialContext connects to the destination server using the provided context.
	DialContext(ctx context.Context, serverID ServerID) (net.Conn, error)
}

// Runner adapter for different consensus protocols including Eventual Consistency/2PC/3PC.
type Runner interface {
	// Init defines setup logic.
	Init(config *Config, peers *Peers, logs LogStore, stable StableStore, dialer Dialer) error

	// UpdatePeers defines peer configuration update logic.
	UpdatePeers(peers *Peers) error

	// Process defines log replication and log commit logic
	// and should be called by Leader role only.
	Process(l *Log) error

	// Shutdown defines destruct logic.
	Shutdown() error
}
