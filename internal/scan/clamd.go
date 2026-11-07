package scan

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxStreamBytes is deliberately smaller than most clamd stream
	// limits. The operator must also configure clamd with compatible limits.
	DefaultMaxStreamBytes int64 = 8 << 20
	maxAllowedStreamBytes int64 = 64 << 20
	streamChunkBytes            = 32 << 10
	maxClamdReplyBytes    int64 = 2048
	defaultClamdTimeout         = 30 * time.Second
)

// Clamd is a local-only INSTREAM adapter. The file-owning product must
// authorize, open, and retain control of the source object. A separate,
// least-privilege clamd process must be isolated by the operating system.
// This adapter is not an HTTP API, quarantine implementation or job queue.
type Clamd struct {
	SocketPath string
	MaxBytes   int64
	Timeout    time.Duration
}

func (c Clamd) settings() (int64, time.Duration, error) {
	if !filepath.IsAbs(c.SocketPath) || strings.IndexByte(c.SocketPath, 0) >= 0 {
		return 0, 0, errors.New("clamd requires an absolute Unix socket path")
	}
	maxBytes := c.MaxBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxStreamBytes
	}
	if maxBytes < 1 || maxBytes > maxAllowedStreamBytes {
		return 0, 0, errors.New("clamd stream size limit is invalid")
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = defaultClamdTimeout
	}
	if timeout < time.Millisecond || timeout > 2*time.Minute {
		return 0, 0, errors.New("clamd timeout is invalid")
	}
	return maxBytes, timeout, nil
}

// Scan streams exactly the declared bytes through a Unix-domain clamd socket.
// It verifies the SHA-256 of the actual bytes and refuses to return a clean
// verdict for missing, extra, or mismatched content. A finite, authorized
// source reader is required. Scan takes ownership of closing that source;
// its Close must unblock a pending Read on cancellation. This does not grant
// filesystem access or release permission.
func (c Clamd) Scan(ctx context.Context, request Request, source io.ReadCloser) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("missing scan context")
	}
	if source == nil {
		return Result{}, errors.New("missing authorized scan content")
	}
	var closeOnce sync.Once
	closeSource := func() { closeOnce.Do(func() { _ = source.Close() }) }
	defer closeSource()
	if err := request.Validate(time.Now().UTC()); err != nil {
		return Result{}, fmt.Errorf("invalid scan request: %w", err)
	}
	maxBytes, timeout, err := c.settings()
	if err != nil {
		return Result{}, err
	}
	if request.SizeBytes > maxBytes {
		return Result{}, errors.New("scan exceeds configured content limit")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stopSource := context.AfterFunc(ctx, closeSource)
	defer stopSource()

	version, err := c.version(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("clamd version check failed: %w", err)
	}
	conn, err := c.connect(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("clamd connection failed: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err := io.WriteString(conn, "zINSTREAM\x00"); err != nil {
		return Result{}, fmt.Errorf("clamd command failed: %w", err)
	}
	hash := sha256.New()
	buf := make([]byte, streamChunkBytes)
	remaining := request.SizeBytes
	for remaining > 0 {
		n := len(buf)
		if remaining < int64(n) {
			n = int(remaining)
		}
		read, readErr := io.ReadFull(source, buf[:n])
		if readErr != nil {
			return Result{}, fmt.Errorf("scan source truncated: %w", readErr)
		}
		if _, err := hash.Write(buf[:read]); err != nil {
			return Result{}, err
		}
		if err := writeChunk(conn, buf[:read]); err != nil {
			return Result{}, fmt.Errorf("clamd stream failed: %w", err)
		}
		remaining -= int64(read)
	}
	// The declared length is not trusted until end-of-stream is checked.
	var excess [1]byte
	n, readErr := source.Read(excess[:])
	if n != 0 || !errors.Is(readErr, io.EOF) {
		return Result{}, errors.New("scan source exceeds declared length or did not end cleanly")
	}
	if hex.EncodeToString(hash.Sum(nil)) != request.SHA256 {
		return Result{}, errors.New("scan source hash does not match request")
	}
	if err := writeChunk(conn, nil); err != nil {
		return Result{}, fmt.Errorf("clamd stream terminator failed: %w", err)
	}
	reply, err := readRecord(conn)
	if err != nil {
		return Result{}, fmt.Errorf("clamd scan reply failed: %w", err)
	}
	verdict, signature, err := parseScanReply(reply)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		SchemaVersion: SchemaVersion,
		RequestID:     request.RequestID,
		OwnerProduct:  request.OwnerProduct,
		ObjectID:      request.ObjectID,
		SHA256:        request.SHA256,
		Verdict:       verdict,
		Engine:        "clamav",
		EngineVersion: version,
		SignatureID:   signature,
		ScannedAt:     time.Now().UTC(),
	}
	if err := result.ValidateFor(request, time.Now().UTC()); err != nil {
		return Result{}, fmt.Errorf("invalid clamd result: %w", err)
	}
	return result, nil
}

func (c Clamd) connect(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (c Clamd) version(ctx context.Context) (string, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := io.WriteString(conn, "zVERSION\x00"); err != nil {
		return "", err
	}
	reply, err := readRecord(conn)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(reply)
	if len(fields) < 2 || fields[0] != "ClamAV" {
		return "", errors.New("unexpected clamd version response")
	}
	version := strings.SplitN(fields[1], "/", 2)[0]
	if !identifier.MatchString(version) {
		return "", errors.New("invalid clamd version identifier")
	}
	return version, nil
}

func writeChunk(w io.Writer, data []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func readRecord(conn net.Conn) (string, error) {
	limited := io.LimitReader(conn, maxClamdReplyBytes+1)
	record, err := bufio.NewReader(limited).ReadBytes(0)
	if err != nil {
		return "", err
	}
	if int64(len(record)) > maxClamdReplyBytes || len(record) == 1 {
		return "", errors.New("invalid clamd reply length")
	}
	return string(record[:len(record)-1]), nil
}

func parseScanReply(reply string) (Verdict, string, error) {
	if reply == "stream: OK" {
		return Clean, "", nil
	}
	if !strings.HasPrefix(reply, "stream: ") || !strings.HasSuffix(reply, " FOUND") {
		return "", "", errors.New("clamd returned an error or unknown scan status")
	}
	signature := strings.TrimSuffix(strings.TrimPrefix(reply, "stream: "), " FOUND")
	if !identifier.MatchString(signature) {
		return "", "", errors.New("invalid clamd signature identifier")
	}
	return Malicious, signature, nil
}
