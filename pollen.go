/*

pollen: Entropy-as-a-Server web server

  Copyright (C) 2012-2013 Dustin Kirkland <dustin.kirkland@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published by
  the Free Software Foundation, version 3 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

package main

import (
	"crypto/sha512"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"os"
	"time"
)

var (
	log *syslog.Writer
	dev *os.File
)

const (
	DefaultSize = 64
)

func handler(w http.ResponseWriter, r *http.Request) {
	challenge := r.FormValue("challenge")
	if challenge == "" {
		http.Error(w, "No challenge value provided", http.StatusBadRequest)
		return
	}

	checksum := sha512.New()
	io.WriteString(checksum, challenge)
	challengeResponse := checksum.Sum(nil)
	dev.Write(challengeResponse)
	log.Info(fmt.Sprintf("Server received challenge from [%s, %s] at [%v]", r.RemoteAddr, r.UserAgent(), time.Now().UnixNano()))
	data := make([]byte, DefaultSize)
	io.ReadAtLeast(dev, data, DefaultSize)
	checksum.Write(data[:DefaultSize])
	seed := checksum.Sum(nil)
	fmt.Fprintf(w, "%x\n%x\n", challengeResponse, seed)
	log.Info(fmt.Sprintf("Server sent response to [%s, %s] at [%v]", r.RemoteAddr, r.UserAgent(), time.Now().UnixNano()))
}

func init() {
	var err error
	log, err = syslog.New(syslog.LOG_ERR, "pollen")
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open syslog:", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) != 4 {
		fatalf("Usage: %s HTTP_PORT HTTPS_PORT DEVICE\n", os.Args[0])
	}

	var err error
	dev, err = os.Create(os.Args[3])
	if err != nil {
		fatalf("Cannot open device: %s\n", err)
	}
	defer dev.Close()

	http.HandleFunc("/", handler)
	httpAddr := fmt.Sprintf(":%s", os.Args[1])
	httpsAddr := fmt.Sprintf(":%s", os.Args[2])
	go func() {
		fatal(http.ListenAndServe(httpAddr, nil))
	}()
	fatal(http.ListenAndServeTLS(httpsAddr, "/etc/pollen/cert.pem", "/etc/pollen/key.pem", nil))
}

func fatal(args ...interface{}) {
	log.Crit(fmt.Sprint(args...))
	fmt.Fprint(os.Stderr, args...)
	os.Exit(1)
}

func fatalf(format string, args ...interface{}) {
	log.Emerg(fmt.Sprintf(format, args...))
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}
