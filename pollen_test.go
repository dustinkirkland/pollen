package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type Suite struct {
	*httptest.Server
	t *testing.T
}

type testHandler struct{}

func (h testHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	handler(w, req)
}

func NewSuite(t *testing.T) *Suite {
	return &Suite{httptest.NewServer(testHandler{}), t}
}

func (s *Suite) Assert(v bool, args ...interface{}) {
	if !v {
		s.t.Error(args...)
	}
}

func (s *Suite) TearDown() {
	s.Server.Close()
}

// EmptySha512 is the SHA512 digest of empty input. You can get this with sha512sum < /dev/null.
const EmptySha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

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
	s.Assert(err == nil, "response error:", err)
	s.Assert(chal == EmptySha512, "expected:", EmptySha512, "got:", chal)
	s.Assert(len(chal) == len(EmptySha512), "invalid response length:", len(chal))
	s.SanityCheck(chal, seed)
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

	challenge_resps := make(map[string]bool)
	seeds := make(map[string]bool)
	challenge := "the bassomatic '76"
	for i := 0; i < UniqueChainRounds; i++ {
		res, err := http.Get(fmt.Sprintf("%s/?challenge=%s", s.URL, url.QueryEscape(challenge)))
		s.Assert(err == nil, "http client error:", err)

		challenge_resp, seed, err := ReadResp(res.Body)
		err = res.Body.Close()
		s.Assert(err == nil, "response error:", err)

		challenge_resps[challenge_resp] = true
		seeds[seed] = true

		challenge = seed
	}
	s.Assert(len(challenge_resps) == UniqueChainRounds, "non-unique challenge response")
	s.Assert(len(seeds) == UniqueChainRounds, "non-unique seed response")
}
