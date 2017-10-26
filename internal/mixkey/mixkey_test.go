// mixkey_test.go - Mix keys tests.
// Copyright (C) 2017  Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mixkey

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEpoch = 0x23 // Way in the past on systems with correct time.

var (
	tmpDir string

	testKeyPath string
	testKey     ecdh.PrivateKey

	testPositiveTags = [][]byte{
		[]byte("Only where we ourselves are responsible for our own interests"),
		[]byte("and are free to sacrifice them has our decision moral value."),
		[]byte("We are neither entitled to be unselfish at someone else's expense"),
		[]byte("nor is there any merit in being unselfish if we have no choice."),
		[]byte("The members of a society who in all respects are made to do the good thing"),
		[]byte("have no title to praise."),
	}
	testNegativeTags = [][]byte{
		[]byte("Once men turned their thinking over to machines in the hope"),
		[]byte("that this would set them free. But that only permitted other"),
		[]byte("men with machines to enslave them."),
	}
)

func TestMixKey(t *testing.T) {
	t.Logf("Temp Dir: %v", tmpDir)

	if ok := t.Run("create", doTestCreate); ok {
		t.Run("load", doTestLoad)
		t.Run("unlink", doTestUnlink)
	} else {
		t.Errorf("create tests failed, skipping load tests")
	}

	// Clean up after all of the tests, by removing the temporary directory
	// that holds keys.
	os.RemoveAll(tmpDir)
}

func doTestCreate(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	k, err := New(tmpDir, testEpoch)
	require.NoError(err, "New()")
	testKeyPath = k.db.Path()
	defer k.Deref()

	t.Logf("db: %v", testKeyPath)
	t.Logf("Public Key: %v", hex.EncodeToString(k.PublicKey().Bytes()))
	t.Logf("Private Key: %v", hex.EncodeToString(k.PrivateKey().Bytes()))
	t.Logf("Epoch: %x", k.Epoch())

	// Save a copy so this can be compared later.
	err = testKey.FromBytes(k.PrivateKey().Bytes())
	require.NoError(err, "testKey save")

	// Ensure that the 0 byte pathological tag case behaves.
	assert.True(k.IsReplay([]byte{}), "IsReplay([]byte{})")

	// Populate the replay filter.
	for _, v := range testPositiveTags {
		isReplay := k.IsReplay(v)
		assert.False(isReplay, "IsReplay() new: %v", string(v))
	}
}

func doTestLoad(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	k, err := New(tmpDir, testEpoch)
	require.NoError(err, "New() load")
	k.SetUnlinkIfExpired(true)
	defer k.Deref()

	assert.Equal(&testKey, k.PrivateKey(), "Serialized private key")
	assert.Equal(testKey.PublicKey(), k.PublicKey(), "Serialized public key")
	assert.Equal(uint64(testEpoch), k.Epoch(), "Serialized epoch")

	// Ensure that the loaded replay filter is consistent.
	assert.True(k.IsReplay([]byte{}), "IsReplay([]byte{})")
	for _, v := range testPositiveTags {
		isReplay := k.IsReplay(v)
		assert.True(isReplay, "IsReplay() load, positive: %v", string(v))
	}
	for _, v := range testNegativeTags {
		isReplay := k.IsReplay(v)
		assert.False(isReplay, "IsReplay() load, negative: %v", string(v))
	}
}

func doTestUnlink(t *testing.T) {
	require := require.New(t)

	// doTestLoad() should have removed the database, unless it failed to load.
	_, err := os.Lstat(testKeyPath)
	require.True(os.IsNotExist(err), "Database should not exist")
}

func init() {
	var err error
	tmpDir, err = ioutil.TempDir("", "mixkey_tests")
	if err != nil {
		panic(err)
	}
}
