package quic

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ExperimentalCloneObjectChunkSize is the fixed number of bytes in a full chunk.
const ExperimentalCloneObjectChunkSize = 1000

// ExperimentalCloneObjectMaxChunks bounds manifest memory and object size.
// Objects can contain at most 2,097,152,000 bytes; an empty object has no chunks.
// The maximum hash manifest occupies 64 MiB and also fits 32-bit object lengths.
const ExperimentalCloneObjectMaxChunks = 2 << 20

// ExperimentalCloneObjectID identifies the complete manifest, not a raw byte digest.
type ExperimentalCloneObjectID [sha256.Size]byte

// ExperimentalCloneObjectManifest is immutable after construction and safe for
// concurrent reads. Its zero value is invalid. It contains no object bytes.
type ExperimentalCloneObjectManifest struct {
	id     ExperimentalCloneObjectID
	size   int64
	hashes [][sha256.Size]byte
}

// ID returns the domain-separated SHA256 of size, chunk size, count and hashes.
func (m ExperimentalCloneObjectManifest) ID() ExperimentalCloneObjectID { return m.id }

// Size returns the exact object length in bytes.
func (m ExperimentalCloneObjectManifest) Size() int64 { return m.size }

// ChunkHashes returns a defensive copy of the ordered chunk hashes.
func (m ExperimentalCloneObjectManifest) ChunkHashes() [][sha256.Size]byte {
	return append([][sha256.Size]byte(nil), m.hashes...)
}

func experimentalCloneObjectCount(size int64) (int, error) {
	// Bound before addition, multiplication, allocation or conversion to int.
	if size < 0 || size > int64(ExperimentalCloneObjectMaxChunks)*ExperimentalCloneObjectChunkSize {
		return 0, errors.New("clone object size out of bounds")
	}
	return int((size + ExperimentalCloneObjectChunkSize - 1) / ExperimentalCloneObjectChunkSize), nil
}

func experimentalCloneObjectIdentity(size int64, hashes [][sha256.Size]byte) ExperimentalCloneObjectID {
	h := sha256.New()
	h.Write([]byte("mycelium-quic/clone-object/v1\x00"))
	var header [24]byte
	binary.BigEndian.PutUint64(header[0:8], uint64(size))
	binary.BigEndian.PutUint64(header[8:16], ExperimentalCloneObjectChunkSize)
	binary.BigEndian.PutUint64(header[16:24], uint64(len(hashes)))
	h.Write(header[:])
	for _, hash := range hashes {
		h.Write(hash[:])
	}
	var id ExperimentalCloneObjectID
	copy(id[:], h.Sum(nil))
	return id
}

// NewExperimentalCloneObjectManifest imports metadata received independently of
// object content. It copies hashes and validates the claimed content identity.
// The caller must authenticate that identity through its own control channel.
func NewExperimentalCloneObjectManifest(id ExperimentalCloneObjectID, size int64, hashes [][sha256.Size]byte) (ExperimentalCloneObjectManifest, error) {
	count, err := experimentalCloneObjectCount(size)
	if err != nil {
		return ExperimentalCloneObjectManifest{}, err
	}
	if len(hashes) != count {
		return ExperimentalCloneObjectManifest{}, errors.New("clone object chunk count mismatch")
	}
	m := ExperimentalCloneObjectManifest{id: id, size: size, hashes: append([][sha256.Size]byte(nil), hashes...)}
	if err := m.Validate(); err != nil {
		return ExperimentalCloneObjectManifest{}, err
	}
	return m, nil
}

// Validate checks bounds, exact chunk count and the complete manifest identity.
func (m ExperimentalCloneObjectManifest) Validate() error {
	count, err := experimentalCloneObjectCount(m.size)
	if err != nil {
		return err
	}
	if len(m.hashes) != count {
		return errors.New("clone object chunk count mismatch")
	}
	if m.id != experimentalCloneObjectIdentity(m.size, m.hashes) {
		return errors.New("clone object identity mismatch")
	}
	return nil
}

func experimentalCloneObjectEnd(r io.ReaderAt, size int64) error {
	var probe [1]byte
	n, err := r.ReadAt(probe[:], size)
	if n != 0 {
		return errors.New("clone object exceeds declared size")
	}
	if err != io.EOF {
		if err != nil {
			return fmt.Errorf("clone object end: %w", err)
		}
		return errors.New("clone object end did not return EOF")
	}
	return nil
}

func experimentalCloneObjectRead(r io.ReaderAt, p []byte, offset int64) error {
	n, err := r.ReadAt(p, offset)
	if n != len(p) {
		if err == nil || err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("clone object short read at %d: %w", offset, err)
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("clone object read at %d: %w", offset, err)
	}
	return nil
}

// BuildExperimentalCloneObjectManifest hashes an exact-size ReaderAt using one
// chunk of scratch space. No bytes or reader are retained. The object must stay
// unchanged during construction. ReaderAt must report EOF beyond its end.
func BuildExperimentalCloneObjectManifest(r io.ReaderAt, size int64) (ExperimentalCloneObjectManifest, error) {
	count, err := experimentalCloneObjectCount(size)
	if err != nil {
		return ExperimentalCloneObjectManifest{}, err
	}
	if r == nil {
		return ExperimentalCloneObjectManifest{}, errors.New("nil clone object reader")
	}
	hashes := make([][sha256.Size]byte, count)
	var buf [ExperimentalCloneObjectChunkSize]byte
	for i := range hashes {
		offset := int64(i) * ExperimentalCloneObjectChunkSize
		length := min(int64(len(buf)), size-offset)
		if err := experimentalCloneObjectRead(r, buf[:length], offset); err != nil {
			return ExperimentalCloneObjectManifest{}, err
		}
		hashes[i] = sha256.Sum256(buf[:length])
	}
	if err := experimentalCloneObjectEnd(r, size); err != nil {
		return ExperimentalCloneObjectManifest{}, err
	}
	return ExperimentalCloneObjectManifest{id: experimentalCloneObjectIdentity(size, hashes), size: size, hashes: hashes}, nil
}

// ExperimentalCloneObjectResolver opens a worker's local immutable object by ID.
// The resolver owns reader lifetime and must keep it usable for the read. For
// concurrent reads it must return ReaderAt implementations safe for that use.
// Implementations must not return a typed nil reader.
type ExperimentalCloneObjectResolver interface {
	ResolveCloneObject(ExperimentalCloneObjectID) (io.ReaderAt, error)
}

// ExperimentalCloneObjectResolverFunc adapts a callback to a resolver.
type ExperimentalCloneObjectResolverFunc func(ExperimentalCloneObjectID) (io.ReaderAt, error)

func (f ExperimentalCloneObjectResolverFunc) ResolveCloneObject(id ExperimentalCloneObjectID) (io.ReaderAt, error) {
	if f == nil {
		return nil, errors.New("nil clone object resolver callback")
	}
	return f(id)
}

// ReadVerifiedChunk resolves a local object and returns a newly allocated chunk
// only after verification. Offset must be chunk-aligned and strictly below Size.
// It reads at most 1001 bytes. Other chunks are verified when requested, not here;
// the resolver must supply a stable immutable object for independent reads.
func (m ExperimentalCloneObjectManifest) ReadVerifiedChunk(resolver ExperimentalCloneObjectResolver, offset int64) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if offset < 0 || offset >= m.size || offset%ExperimentalCloneObjectChunkSize != 0 {
		return nil, errors.New("clone object chunk offset out of bounds or unaligned")
	}
	if resolver == nil {
		return nil, errors.New("nil clone object resolver")
	}
	r, err := resolver.ResolveCloneObject(m.id)
	if err != nil {
		return nil, fmt.Errorf("resolve clone object: %w", err)
	}
	if r == nil {
		return nil, errors.New("nil clone object reader")
	}
	length := min(int64(ExperimentalCloneObjectChunkSize), m.size-offset)
	buf := make([]byte, length)
	if err := experimentalCloneObjectRead(r, buf, offset); err != nil {
		return nil, err
	}
	if sha256.Sum256(buf) != m.hashes[offset/ExperimentalCloneObjectChunkSize] {
		return nil, errors.New("clone object chunk hash mismatch")
	}
	if err := experimentalCloneObjectEnd(r, m.size); err != nil {
		return nil, err
	}
	return buf, nil
}
