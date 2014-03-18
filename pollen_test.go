package main

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

type logEntry struct {
	severity string
	message  string
}

type localLogger struct {
	logs []logEntry
}

func (l *localLogger) Close() error {
	l.logs = append(l.logs, logEntry{"close", ""})
	return nil
}

func (l *localLogger) Info(msg string) error {
	l.logs = append(l.logs, logEntry{"info", msg})
	return nil
}

func (l *localLogger) Err(msg string) error {
	l.logs = append(l.logs, logEntry{"err", msg})
	return nil
}

func (l *localLogger) Crit(msg string) error {
	l.logs = append(l.logs, logEntry{"crit", msg})
	return nil
}

func (l *localLogger) Emerg(msg string) error {
	l.logs = append(l.logs, logEntry{"emerg", msg})
	return nil
}

type Suite struct {
	*httptest.Server
	t      *testing.T
	dev    io.ReadWriter
	logger *localLogger
	pollen *PollenServer
}

func NewSuite(t *testing.T) *Suite {
	/* hardcode /dev/urandom for testing purposes */
	dev, err := os.OpenFile("/dev/urandom", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Cannot open device: %s\n", err)
	}
	return NewSuiteWithDev(t, dev)
}

func NewSuiteWithDev(t *testing.T, dev io.ReadWriter) *Suite {
	logger := &localLogger{}
	handler := &PollenServer{randomSource: dev, log: logger, readSize: 64}
	return &Suite{httptest.NewServer(handler), t, dev, logger, handler}
}

func (s *Suite) Assert(v bool, args ...interface{}) {
	if !v {
		s.t.Error(args...)
	}
}

func (s *Suite) TearDown() {
	s.Server.Close()
	if closer, ok := s.dev.(io.Closer); ok {
		closer.Close()
	}
}

// MustScan scans a single token. There must be a token available and it must
// scan successfully or an error is returned.
func MustScan(s *bufio.Scanner) error {
	if !s.Scan() {
		return fmt.Errorf("Missing expected text")
	}
	return s.Err()
}

// ParseResp parses the pollen response to the challenge & response
// in the output, as well as any error that occurred with reading or
// validating it.
func ReadResp(r io.Reader) (challenge, response string, err error) {
	scanner := bufio.NewScanner(r)
	if err = MustScan(scanner); err != nil {
		return
	}
	challenge = scanner.Text()
	if err = MustScan(scanner); err != nil {
		return
	}
	response = scanner.Text()
	return
}

// CheckHex returns an error if the given string is not valid hex.
func CheckHex(s string) error {
	_, err := hex.DecodeString(s)
	return err
}

// TestNoChallenge tests the pollen service when no challenge is given
// in the request.
func TestNoChallenge(t *testing.T) {
	s := NewSuite(t)
	defer s.TearDown()

	res, err := http.Get(s.URL)
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	chal, seed, err := ReadResp(res.Body)
	s.Assert(err != nil, "response error:", err)
	s.Assert(res.StatusCode == http.StatusBadRequest, "didn't get Bad Request, got: ", res.Status)
	s.Assert(chal == usePollinateError, "got the wrong error message:", chal)
	s.Assert(seed == "", "got extra messages:", seed)
}

func (s *Suite) SanityCheck(chal, seed string) {
	s.Assert(chal != seed, "challenge response and seed were the same!")
	s.Assert(len(chal) == len(seed), "challenge response and seed length not equal")
	s.Assert(CheckHex(chal) == nil, "invalid hex:", chal)
	s.Assert(CheckHex(seed) == nil, "invalid hex:", seed)
}

// PorkChopSha512 is $(echo -n "pork chop sandwiches" | sha512sum)
const PorkChopSha512 = "a75751ccd71ba00d7b6c3b74cc0c02373f3f26c14dfe47afd580b0d87bf9fd8cebc73ea29b1cae15586e0d118922342ea7e94d0cb73a0f918d7d8c7ec065e873"

// TestPorkChopSandwiches tests the pollen service when given
// pork chop sandwiches.
func TestPorkChopSandwiches(t *testing.T) {
	s := NewSuite(t)
	defer s.TearDown()

	res, err := http.Get(s.URL + "?challenge=pork+chop+sandwiches")
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	chal, resp, err := ReadResp(res.Body)
	s.Assert(err == nil, "response error:", err)
	s.Assert(chal == PorkChopSha512, "expected:", PorkChopSha512, "got:", chal)
	s.SanityCheck(chal, resp)
}

// TestPorkChopPost tests the pollen service when the
// pork chop sandwiches are POSTed.
func TestPostChopSandwiches(t *testing.T) {
	s := NewSuite(t)
	defer s.TearDown()

	res, err := http.PostForm(s.URL, url.Values{"challenge": []string{"pork chop sandwiches"}})
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	chal, resp, err := ReadResp(res.Body)
	s.Assert(err == nil, "response error:", err)
	s.Assert(chal == PorkChopSha512, "expected:", PorkChopSha512, "got:", chal)
	s.SanityCheck(chal, resp)
}

const UniqueChainRounds = 100

// TestUniqueChaining tests the uniqueness of seeds and challenge responses
// when fed into successive requests as challenges.
func TestUniqueChaining(t *testing.T) {
	s := NewSuite(t)
	defer s.TearDown()

	challengeResps := make(map[string]bool)
	seeds := make(map[string]bool)
	challenge := "the bassomatic '76"
	for i := 0; i < UniqueChainRounds; i++ {
		res, err := http.Get(fmt.Sprintf("%s/?challenge=%s", s.URL, url.QueryEscape(challenge)))
		s.Assert(err == nil, "http client error:", err)

		challengeResp, seed, err := ReadResp(res.Body)
		err = res.Body.Close()
		s.Assert(err == nil, "response error:", err)

		challengeResps[challengeResp] = true
		seeds[seed] = true

		challenge = seed
	}
	s.Assert(len(challengeResps) == UniqueChainRounds, "non-unique challenge response")
	s.Assert(len(seeds) == UniqueChainRounds, "non-unique seed response")
}

// TestUniqueSeeds tests the uniqueness of responses to the same challenge
func TestUniqueSeeds(t *testing.T) {
	s := NewSuite(t)
	defer s.TearDown()

	challengeResps := make(map[string]bool)
	seeds := make(map[string]bool)
	challenge := "the bassomatic '76"
	for i := 0; i < UniqueChainRounds; i++ {
		res, err := http.Get(fmt.Sprintf("%s/?challenge=%s", s.URL, url.QueryEscape(challenge)))
		s.Assert(err == nil, "http client error:", err)

		challengeResp, seed, err := ReadResp(res.Body)
		err = res.Body.Close()
		s.Assert(err == nil, "response error:", err)

		challengeResps[challengeResp] = true
		seeds[seed] = true
	}
	s.Assert(len(challengeResps) == 1, "more than one sha sum for the same challenge")
	s.Assert(len(seeds) == UniqueChainRounds, "non-unique seed response")
}

// DilbertRandom is 64 bytes of pure nines
var DilbertRandom = "ninenineninenineninenineninenineninenineninenineninenineninenine"
var DilbertRandomSHA1 = "f73655d899f0f3d181d8e94b163e774a05abdd3b55123d0b9b2f18ad8c05c76e6fde93ba9dfc350acc2e378b59dd6962fc305b741f9a5b7edb16435e61a86b96"

// TestCannedContent exercises the input and output removing the randomness of rand
func TestCannedContent(t *testing.T) {
	b := bytes.NewBufferString(DilbertRandom)
	s := NewSuiteWithDev(t, b)
	defer s.TearDown()

	res, err := http.Get(s.URL + "?challenge=pork+chop+sandwiches")
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	chal, seed, err := ReadResp(res.Body)
	s.Assert(err == nil, "response error:", err)
	s.Assert(chal == PorkChopSha512, "expected:", PorkChopSha512, "got:", chal)
	s.SanityCheck(chal, seed)
	// Check that the 'random' seed we got back was appropriately mixed
	// with the challenge
	s.Assert(seed != DilbertRandom, "got the raw random content")
	s.Assert(seed != DilbertRandomSHA1, "got the sha of random content without the challenge")
	expectedSum := sha512.New()
	io.WriteString(expectedSum, "pork chop sandwiches")
	io.WriteString(expectedSum, DilbertRandom)
	expectedSeed := fmt.Sprintf("%x", expectedSum.Sum(nil))
	s.Assert(seed == expectedSeed, "expected:", expectedSeed, "got:", seed)
	// We can also check that the challenge was correctly written to our random device
	// b.Bytes() is the remainder of our buffer, and Buffer writes at the end
	// This also shows that we didn't write the raw request
	writtenBytesInHex := fmt.Sprintf("%x", string(b.Bytes()))
	s.Assert(PorkChopSha512 == writtenBytesInHex, "expected:", PorkChopSha512, "got:", writtenBytesInHex)
}

// TestSizeMatters asserts that changing 'size' changes how many bytes we read
func TestSizeMatters(t *testing.T) {
	b := bytes.NewBufferString(DilbertRandom)
	s := NewSuiteWithDev(t, b)
	defer s.TearDown()

	s.pollen.readSize = 32
	res, err := http.Get(s.URL + "?challenge=xxx")
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	_, _, err = ReadResp(res.Body)
	s.Assert(err == nil, "response err:", err)
	// If we set the readSize to 32 bytes, then we should only have that
	// much data read from the buffer
	remaining := b.Bytes()
	// We have to add the 64 bytes that we wrote because of the challenge
	s.Assert(len(remaining) == 32+64, "wrong number of bytes remaining, expected 96 got:", len(remaining))
}

// TestExtraSize asserts that you can make size 'big'
func TestExtraSize(t *testing.T) {
	b := bytes.NewBufferString(DilbertRandom)
	s := NewSuiteWithDev(t, b)
	defer s.TearDown()

	// We only start with 64 bytes of "nine" but we add the challenge to the pool
	s.pollen.readSize = 128
	res, err := http.Get(s.URL + "?challenge=xxx")
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	_, _, err = ReadResp(res.Body)
	s.Assert(err == nil, "response err:", err)
	remaining := b.Bytes()
	s.Assert(len(remaining) == 0, "wrong number of bytes remaining, expected 0 got:", len(remaining))
}

type OnlyReader struct {
	*bytes.Buffer
}

func (o *OnlyReader) Write([]byte) (int, error) {
	return 0, &os.PathError{Op: "write", Path: "<mem>", Err: os.ErrPermission}
}

// We have to implement this because bytes.Buffer does, and io.WriteString can chose to use it
func (o *OnlyReader) WriteString(string) (int, error) {
	return 0, &os.PathError{Op: "write", Path: "<mem>", Err: os.ErrPermission}
}

// TestWriteFailure tests that if we can't write to our random device, we keep going
func TestWriteFailure(t *testing.T) {
	b := &OnlyReader{bytes.NewBufferString(DilbertRandom)}
	s := NewSuiteWithDev(t, b)
	defer s.TearDown()

	res, err := http.Get(s.URL + "?challenge=xxx")
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	chal, seed, err := ReadResp(res.Body)
	s.Assert(err == nil, "response err:", err)
	s.SanityCheck(chal, seed)
	// Failing to write to the random device is logged
	s.Assert(len(s.logger.logs) == 3, "expected 3 log messages, got:", len(s.logger.logs))
	start := "Cannot write to random device at ["
	s.Assert(s.logger.logs[0].severity == "err" &&
		s.logger.logs[0].message[:len(start)] == start,
		"didn't get the expected error message, got:", s.logger.logs[0])
	start = "Server received challenge from ["
	s.Assert(s.logger.logs[1].severity == "info" &&
		s.logger.logs[1].message[:len(start)] == start,
		"didn't get the expected error message, got:", s.logger.logs[1])
	start = "Server sent response to ["
	s.Assert(s.logger.logs[2].severity == "info" &&
		s.logger.logs[2].message[:len(start)] == start,
		"didn't get the expected error message, got:", s.logger.logs[2])
}

type FailingReader struct {
	*bytes.Buffer
}

func (o *FailingReader) Read([]byte) (int, error) {
	return 0, &os.PathError{Op: "read", Path: "<mem>", Err: os.ErrPermission}
}

// TestReadFailure tests that if we can't read from our random device it is immediately fatal
func TestReadFailure(t *testing.T) {
	// No random data to give to the client
	b := &FailingReader{bytes.NewBufferString("")}
	s := NewSuiteWithDev(t, b)
	defer s.TearDown()

	res, err := http.Get(s.URL + "?challenge=xxx")
	s.Assert(err == nil, "http client error:", err)
	defer res.Body.Close()
	errMsg, _, err := ReadResp(res.Body)
	s.Assert(err != nil, "response error:", err)
	s.Assert(errMsg == "Failed to read from random device", "wrong error: ", errMsg)
	s.Assert(res.StatusCode == http.StatusInternalServerError, "wrong status: ", res.Status)
	s.Assert(len(s.logger.logs) == 2, "expected 2 log messages, got: ", len(s.logger.logs))
	start := "Server received challenge from ["
	s.Assert(s.logger.logs[0].severity == "info" &&
		s.logger.logs[0].message[:len(start)] == start,
		"didn't get the expected error message, got:", s.logger.logs[0])
	start = "Cannot read from random device at ["
	s.Assert(s.logger.logs[1].severity == "err" &&
		s.logger.logs[1].message[:len(start)] == start,
		"didn't get the expected error message, got:", s.logger.logs[1])
}
