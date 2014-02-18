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
	"crypto/rand"
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
	checksum := sha512.New()
	io.WriteString(checksum, r.FormValue("challenge"))
	challengeResponse := checksum.Sum(nil)
	dev.Write(challengeResponse)
	log.Info(fmt.Sprintf("Server received challenge from [%s, %s] at [%v]", r.RemoteAddr, r.UserAgent(), time.Now().UnixNano()))
	data := make([]byte, DefaultSize)
	io.ReadAtLeast(rand.Reader, data, DefaultSize)
	checksum.Write(data[:DefaultSize])
	seed := checksum.Sum(nil)
	fmt.Fprintf(w, "%x\n%x\n", challengeResponse, seed)
	log.Info(fmt.Sprintf("Server sent response to [%s, %s] at [%v]", r.RemoteAddr, r.UserAgent(), time.Now().UnixNano()))
}

func init() {
	log, _ = syslog.New(syslog.LOG_ERR, "pollen")
}

func main() {
	dev, _ = os.Create(os.Args[3])
	http.HandleFunc("/", handler)
	httpPort := fmt.Sprintf(":%s", os.Args[1])
	httpsPort := fmt.Sprintf(":%s", os.Args[2])
	go http.ListenAndServe(httpPort, nil)
	go http.ListenAndServeTLS(httpsPort, "/etc/pollen/cert.pem", "/etc/pollen/key.pem", nil)
	time.Sleep(1e9 * 1e9)
	dev.Close()
}
