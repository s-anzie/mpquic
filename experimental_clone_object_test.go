package quic

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"sync"
	"testing"
)

func cloneObjectResolver(data []byte) ExperimentalCloneObjectResolverFunc {
	return func(ExperimentalCloneObjectID) (io.ReaderAt, error) { return bytes.NewReader(data), nil }
}

func TestExperimentalCloneObjectRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 999, 1000, 1001, 2501} {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*17 + i/1000)
		}
		m, err := BuildExperimentalCloneObjectManifest(bytes.NewReader(data), int64(size))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Validate(); err != nil {
			t.Fatal(err)
		}
		if m.Size() != int64(size) {
			t.Fatal("wrong size")
		}
		imported, err := NewExperimentalCloneObjectManifest(m.ID(), m.Size(), m.ChunkHashes())
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		for offset := int64(0); offset < m.Size(); offset += 1000 {
			chunk, err := imported.ReadVerifiedChunk(cloneObjectResolver(data), offset)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, chunk...)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: wrong content", size)
		}
		if size == 0 {
			if _, err := m.ReadVerifiedChunk(cloneObjectResolver(data), 0); err == nil {
				t.Fatal("empty object has no chunks")
			}
		}
	}
}

func TestExperimentalCloneObjectManifestIntegrity(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 1001)
	m, err := BuildExperimentalCloneObjectManifest(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	hashes := m.ChunkHashes()
	if hashes[0] != sha256.Sum256(data[:1000]) || hashes[1] != sha256.Sum256(data[1000:]) {
		t.Fatal("wrong chunk hashes")
	}
	imported, err := NewExperimentalCloneObjectManifest(m.ID(), m.Size(), hashes)
	if err != nil {
		t.Fatal(err)
	}
	hashes[0][0] ^= 1
	exported := imported.ChunkHashes()
	exported[0][0] ^= 1
	if err := imported.Validate(); err != nil {
		t.Fatalf("manifest aliases input or output: %v", err)
	}
	for _, size := range []int64{-1, math.MinInt64, math.MaxInt64, int64(ExperimentalCloneObjectMaxChunks)*ExperimentalCloneObjectChunkSize + 1, 1002} {
		if _, err := NewExperimentalCloneObjectManifest(m.ID(), size, m.ChunkHashes()); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
	if _, err := NewExperimentalCloneObjectManifest(m.ID(), m.Size(), hashes); err == nil {
		t.Fatal("accepted altered hash")
	}
	if _, err := NewExperimentalCloneObjectManifest(m.ID(), m.Size(), m.ChunkHashes()[:1]); err == nil {
		t.Fatal("accepted missing hash")
	}
	swapped := m.ChunkHashes()
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if _, err := NewExperimentalCloneObjectManifest(m.ID(), m.Size(), swapped); err == nil {
		t.Fatal("accepted reordered hashes")
	}
	if err := (ExperimentalCloneObjectManifest{}).Validate(); err == nil {
		t.Fatal("accepted zero manifest")
	}
	if count, err := experimentalCloneObjectCount(int64(ExperimentalCloneObjectMaxChunks) * ExperimentalCloneObjectChunkSize); err != nil || count != ExperimentalCloneObjectMaxChunks {
		t.Fatal("maximum size rejected")
	}
}

func TestExperimentalCloneObjectBadContent(t *testing.T) {
	data := bytes.Repeat([]byte{9}, 2001)
	m, err := BuildExperimentalCloneObjectManifest(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(data)
	corrupt[1000] ^= 1
	for _, tc := range []struct {
		name   string
		data   []byte
		offset int64
	}{
		{"corrupt", corrupt, 1000},
		{"truncated full chunk", data[:999], 0},
		{"truncated last chunk", data[:2000], 2000},
		{"excess bytes", append(bytes.Clone(data), 0), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := m.ReadVerifiedChunk(cloneObjectResolver(tc.data), tc.offset)
			if err == nil || b != nil {
				t.Fatal("returned unverified content")
			}
		})
	}
	for _, size := range []int64{2000, 2002, -1, math.MaxInt64, 65536001} {
		if _, err := BuildExperimentalCloneObjectManifest(bytes.NewReader(data), size); err == nil {
			t.Fatalf("accepted incorrect length %d", size)
		}
	}
}

func TestExperimentalCloneObjectOffsetsAndResolver(t *testing.T) {
	m, err := BuildExperimentalCloneObjectManifest(bytes.NewReader(make([]byte, 1001)), 1001)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	resolver := ExperimentalCloneObjectResolverFunc(func(id ExperimentalCloneObjectID) (io.ReaderAt, error) {
		calls++
		if id != m.ID() {
			t.Fatal("wrong resolver identity")
		}
		return bytes.NewReader(make([]byte, 1001)), nil
	})
	for _, offset := range []int64{-1, math.MinInt64, 1, 999, 1001, 2000, math.MaxInt64} {
		if b, err := m.ReadVerifiedChunk(resolver, offset); err == nil || b != nil {
			t.Fatalf("accepted offset %d", offset)
		}
	}
	if calls != 0 {
		t.Fatal("resolved invalid offset")
	}
	if _, err := m.ReadVerifiedChunk(resolver, 1000); err != nil || calls != 1 {
		t.Fatal("valid offset failed", err)
	}
	sentinel := errors.New("unavailable")
	failing := ExperimentalCloneObjectResolverFunc(func(ExperimentalCloneObjectID) (io.ReaderAt, error) { return nil, sentinel })
	if _, err := m.ReadVerifiedChunk(failing, 0); !errors.Is(err, sentinel) {
		t.Fatal("lost resolver error")
	}
	var nilCallback ExperimentalCloneObjectResolverFunc
	nilReader := ExperimentalCloneObjectResolverFunc(func(ExperimentalCloneObjectID) (io.ReaderAt, error) { return nil, nil })
	for _, r := range []ExperimentalCloneObjectResolver{nil, nilCallback, nilReader} {
		if _, err := m.ReadVerifiedChunk(r, 0); err == nil {
			t.Fatal("accepted nil dependency")
		}
	}
	if _, err := BuildExperimentalCloneObjectManifest(nil, 0); err == nil {
		t.Fatal("accepted nil builder reader")
	}
}

type cloneObjectReaderFunc func([]byte, int64) (int, error)

func (f cloneObjectReaderFunc) ReadAt(p []byte, off int64) (int, error) { return f(p, off) }

func TestExperimentalCloneObjectReadContracts(t *testing.T) {
	sentinel := errors.New("disk failure")
	for _, readErr := range []error{nil, io.EOF, sentinel} {
		r := cloneObjectReaderFunc(func(p []byte, off int64) (int, error) { return 0, readErr })
		_, err := BuildExperimentalCloneObjectManifest(r, 1)
		expected := readErr
		if expected == nil || expected == io.EOF {
			expected = io.ErrUnexpectedEOF
		}
		if !errors.Is(err, expected) {
			t.Fatalf("expected %v, got %v", expected, err)
		}
	}
	data := make([]byte, 1001)
	var reads []int
	r := cloneObjectReaderFunc(func(p []byte, off int64) (int, error) {
		reads = append(reads, len(p))
		n, err := bytes.NewReader(data).ReadAt(p, off)
		if n == len(p) {
			return n, io.EOF
		}
		return n, err
	})
	m, err := BuildExperimentalCloneObjectManifest(r, 1001)
	if err != nil {
		t.Fatal(err)
	}
	reads = nil
	resolver := ExperimentalCloneObjectResolverFunc(func(ExperimentalCloneObjectID) (io.ReaderAt, error) { return r, nil })
	if _, err := m.ReadVerifiedChunk(resolver, 0); err != nil {
		t.Fatal(err)
	}
	if len(reads) != 2 || reads[0] != 1000 || reads[1] != 1 {
		t.Fatalf("unbounded read: %v", reads)
	}
}

func TestExperimentalCloneObjectConcurrentReads(t *testing.T) {
	data := bytes.Repeat([]byte{42}, 2501)
	m, err := BuildExperimentalCloneObjectManifest(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()
			b, err := m.ReadVerifiedChunk(cloneObjectResolver(data), offset)
			if err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(b, data[offset:offset+int64(len(b))]) {
				t.Error("wrong chunk")
			}
			b[0] = 0 // Returned bytes belong exclusively to this caller.
		}(int64(i%3) * 1000)
	}
	wg.Wait()
}
