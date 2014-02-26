package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type logEntry struct {
	severity string
	message string
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
	t *testing.T
	dev *os.File
	logger *localLogger
}

func NewSuite(t *testing.T) *Suite {
	dev, err := os.OpenFile(*device, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("Cannot open device: %s\n", err)
	}
	logger := &localLogger{}
	return &Suite{httptest.NewServer(&PollenServer{randomSource: dev, log: logger}), t, dev, logger}
}

func (s *Suite) Assert(v bool, args ...interface{}) {
	if !v {
		s.t.Error(args...)
	}
}

func (s *Suite) TearDown() {
	s.Server.Close()
	s.dev.Close()
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
	_, _, err = ReadResp(res.Body)
	s.Assert(err != nil, "response error:", err)
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
