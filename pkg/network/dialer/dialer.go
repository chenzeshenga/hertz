/*
 * Copyright 2022 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dialer

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"runtime"
	"time"

	"github.com/cloudwego/hertz/pkg/network"
)

var defaultDialer network.Dialer

var (
	dunno     = []byte("???")
	centerDot = []byte("·")
	dot       = []byte(".")
	slash     = []byte("/")
)

func getDialerName(dialer network.Dialer) string {
	typ := reflect.ValueOf(dialer)
	return typ.Elem().Type().PkgPath()
}

func SetDialer(dialer network.Dialer) {
	// 通过反射获取dialer包名
	fmt.Printf("##### SetDialer: %v\n", getDialerName(dialer))
	stack := stack(2)

	fmt.Printf("##### stack:\n%s\n%s\n",
		timeFormat(time.Now()), stack)
	defaultDialer = dialer
}

func stack(skip int) []byte {
	buf := new(bytes.Buffer) // the returned data
	// As we loop, we open files and read them. These variables record the currently
	// loaded file.
	var lines [][]byte
	var lastFile string
	for i := skip; ; i++ { // Skip the expected number of frames
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		// Print this much at least.  If we can't find the source, it won't show.
		fmt.Fprintf(buf, "%s:%d (0x%x)\n", file, line, pc)
		if file != lastFile {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				continue
			}
			lines = bytes.Split(data, []byte{'\n'})
			lastFile = file
		}
		fmt.Fprintf(buf, "\t%s: %s\n", function(pc), source(lines, line))
	}
	return buf.Bytes()
}

// source returns a space-trimmed slice of the n'th line.
func source(lines [][]byte, n int) []byte {
	n-- // in stack trace, lines are 1-indexed but our array is 0-indexed
	if n < 0 || n >= len(lines) {
		return dunno
	}
	return bytes.TrimSpace(lines[n])
}

// function returns, if possible, the name of the function containing the PC.
func function(pc uintptr) []byte {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return dunno
	}
	name := []byte(fn.Name())
	// The name includes the path name to the package, which is unnecessary
	// since the file name is already included.  Plus, it has center dots.
	// That is, we see
	//	runtime/debug.*T·ptrmethod
	// and want
	//	*T.ptrmethod
	// Also the package path might contains dot (e.g. code.google.com/...),
	// so first eliminate the path prefix
	if lastSlash := bytes.LastIndex(name, slash); lastSlash >= 0 {
		name = name[lastSlash+1:]
	}
	if period := bytes.Index(name, dot); period >= 0 {
		name = name[period+1:]
	}
	name = bytes.Replace(name, centerDot, dot, -1)
	return name
}

func timeFormat(t time.Time) string {
	timeString := t.Format("2006/01/02 - 15:04:05")
	return timeString
}

func DialConnection(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
	return defaultDialer.DialConnection(network, address, timeout, tlsConfig)
}

func DialTimeout(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn net.Conn, err error) {
	return defaultDialer.DialTimeout(network, address, timeout, tlsConfig)
}

// AddTLS is used to add tls to a persistent connection, i.e. negotiate a TLS session. If conn is already a TLS
// tunnel, this function establishes a nested TLS session inside the encrypted channel.
func AddTLS(conn network.Conn, tlsConfig *tls.Config) (network.Conn, error) {
	return defaultDialer.AddTLS(conn, tlsConfig)
}
