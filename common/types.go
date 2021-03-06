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

// Package common defines some common types which are used by multiple modules.
package common

const (
	// AddressLength is the fixed length of a ThunderDB node address.
	AddressLength = 20
	// UUIDLength is the fixed length of a UUID.
	UUIDLength = 16
)

// Address is a ThunderDB node address.
type Address [AddressLength]byte

// UUID is a unique identity which may be used as a Raft transaction ID.
type UUID [UUIDLength]byte
