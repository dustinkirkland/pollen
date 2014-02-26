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
	httpPort  = flag.String("http-port", "80", "The HTTP port on which to listen")
	httpsPort = flag.String("https-port", "443", "The HTTPS port on which to listen")
	device    = flag.String("device", "/dev/urandom", "The device to use for reading and writing random data")
	size      = flag.Int("bytes", 64, "The size in bytes to transmit and receive each time")
	cert      = flag.String("cert", "/etc/pollen/cert.pem", "The full path to cert.pem")
	key       = flag.String("key", "/etc/pollen/key.pem", "The full path to key.pem")
	log *syslog.Writer
	dev *os.File
)

type PollenServer struct {
}

func (p *PollenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	challenge := r.FormValue("challenge")
	if challenge == "" {
		http.Error(w, "Please use the pollinate client.  'sudo apt-get install pollinate' or download from: https://bazaar.launchpad.net/~pollinate/pollinate/trunk/view/head:/pollinate", http.StatusBadRequest)
		return
	}
	checksum := sha512.New()
	io.WriteString(checksum, challenge)
	challengeResponse := checksum.Sum(nil)
	var err error
	_, err = dev.Write(challengeResponse)
	if err != nil {
		/* Non-fatal error, but let's log this to syslog */
		log.Err(fmt.Sprintf("Cannot write to random device at [%v]", time.Now().UnixNano()))
	}
	log.Info(fmt.Sprintf("Server received challenge from [%s, %s] at [%v]", r.RemoteAddr, r.UserAgent(), time.Now().UnixNano()))
	data := make([]byte, *size)
	_, err = io.ReadFull(dev, data)
	if err != nil {
		/* Fatal error for this connection, if we can't read from device */
		log.Err(fmt.Sprintf("Cannot read from random device at [%v]", time.Now().UnixNano()))
		http.Error(w, "Failed to read from random device", 500)
		return
	}
	checksum.Write(data[:*size])
	/* The checksum of the bytes from /dev/urandom is simply for print-ability, when debugging */
	seed := checksum.Sum(nil)
	fmt.Fprintf(w, "%x\n%x\n", challengeResponse, seed)
	log.Info(fmt.Sprintf("Server sent response to [%s, %s] at [%v]", r.RemoteAddr, r.UserAgent(), time.Now().UnixNano()))
}

func init() {
	var err error
	log, err = syslog.New(syslog.LOG_ERR, "pollen")
	if err != nil {
		fatalf("Cannot open syslog:", err)
	}
	dev, err = os.OpenFile(*device, os.O_RDWR, 0)
	if err != nil {
		fatalf("Cannot open device: %s\n", err)
	}
}

func main() {
	flag.Parse()
	defer dev.Close()
	if *httpPort == "" && *httpsPort == "" {
		fatal("Nothing to do if http and https are both disabled")
	}
	handler := &PollenServer{}
	httpAddr := fmt.Sprintf(":%s", *httpPort)
	httpsAddr := fmt.Sprintf(":%s", *httpsPort)
	http.Handle("/", handler)
	go func() {
		fatal(http.ListenAndServe(httpAddr, nil))
	}()
	fatal(http.ListenAndServeTLS(httpsAddr, *cert, *key, nil))
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
