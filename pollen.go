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
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"os"
	"time"
)

var (
	httpAddr  = flag.String("http-addr", ":80", "The HTTP address:port on which to listen")
	httpsAddr = flag.String("https-addr", ":443", "The HTTPS address:port on which to listen")
	device    = flag.String("device", "/dev/urandom", "The device to use for reading and writing random data")
	size      = flag.Int("bytes", 64, "The size in bytes to transmit and receive each time")
	cert      = flag.String("cert", "/etc/pollen/cert.pem", "The full path to cert.pem")
	key       = flag.String("key", "/etc/pollen/key.pem", "The full path to key.pem")

	log *syslog.Writer
	dev *os.File
)

func handler(w http.ResponseWriter, r *http.Request) {
	checksum := sha512.New()
	io.WriteString(checksum, r.FormValue("challenge"))
	challengeResponse := checksum.Sum(nil)
	dev.Write(challengeResponse)
	log.Info(fmt.Sprintf("Server received challenge from [%s, %s] at [%v]", r.RemoteAddr, r.UserAgent(), time.Now().UnixNano()))
	data := make([]byte, *size)
	io.ReadAtLeast(dev, data, *size)
	checksum.Write(data[:*size])
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
	flag.Parse()
	if *httpAddr == "" && *httpsAddr == "" {
		fatal("Nothing to do if http and https are both disabled")
	}

	var err error
	dev, err = os.OpenFile(*device, os.O_RDWR, 0)
	if err != nil {
		fatalf("Cannot open device: %s\n", err)
	}
	defer dev.Close()

	http.HandleFunc("/", handler)
	go func() {
		fatal(http.ListenAndServe(*httpAddr, nil))
	}()
	fatal(http.ListenAndServeTLS(*httpsAddr, *cert, *key, nil))
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
