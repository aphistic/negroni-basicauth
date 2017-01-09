package basicauth

import (
	"errors"
	"testing"

	"net/http"

	"encoding/base64"

	"fmt"

	"github.com/aphistic/sweet"
	. "github.com/onsi/gomega"
)

func newReq() *http.Request {
	return &http.Request{
		Header: make(http.Header),
	}
}

type TestWriter struct {
	header     http.Header
	LastStatus int
}

func newRes() *TestWriter {
	return &TestWriter{
		header: make(http.Header),
	}
}

func (w *TestWriter) Header() http.Header {
	return w.header
}

func (w *TestWriter) Write(d []byte) (int, error) {
	return 0, errors.New("Not implemented")
}

func (w *TestWriter) WriteHeader(statusCode int) {
	w.LastStatus = statusCode
}

func Test(t *testing.T) {
	sweet.SetUpAllTests(func(tt *testing.T) {
		RegisterTestingT(tt)
	})

	sweet.RunSuite(t, &BasicSuite{})
}

type BasicSuite struct{}

func (s *BasicSuite) TestGetCreds(t *testing.T) {
	u, p := getCreds(nil)
	Expect(u).To(Equal(""))
	Expect(p).To(Equal(""))

	req := newReq()
	req.Header.Add("Something", "Not Auth")
	u, p = getCreds(req)
	Expect(u).To(Equal(""))
	Expect(p).To(Equal(""))

	req = newReq()
	req.Header.Add("Authorization", "NotBasic")
	u, p = getCreds(req)
	Expect(u).To(Equal(""))
	Expect(p).To(Equal(""))

	req = newReq()
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(":mypass")))
	u, p = getCreds(req)
	Expect(u).To(Equal(""))
	Expect(p).To(Equal("mypass"))

	req = newReq()
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("myuser:")))
	u, p = getCreds(req)
	Expect(u).To(Equal("myuser"))
	Expect(p).To(Equal(""))

	req = newReq()
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("myuser")))
	u, p = getCreds(req)
	Expect(u).To(Equal(""))
	Expect(p).To(Equal(""))

	req = newReq()
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("myuser:mypass")))
	u, p = getCreds(req)
	Expect(u).To(Equal("myuser"))
	Expect(p).To(Equal("mypass"))
}

func (s *BasicSuite) TestBasicFuncInvalidAuth(t *testing.T) {
	f := BasicFunc("myrealm", func(user, pass string, req *http.Request) bool {
		return false
	})

	res := newRes()
	req := newReq()

	nextCalled := false
	next := func(res http.ResponseWriter, req *http.Request) {
		nextCalled = true
	}

	f(res, req, next)

	Expect(res.LastStatus).To(Equal(http.StatusUnauthorized))
	Expect(res.Header().Get("WWW-Authenticate")).To(Equal(`Basic realm="myrealm"`))
	Expect(nextCalled).To(BeFalse())
}

func (s *BasicSuite) TestBasicFuncValidAuth(t *testing.T) {
	foundUser := ""
	foundPass := ""
	var foundReq *http.Request

	f := BasicFunc("myrealm", func(user, pass string, req *http.Request) bool {
		foundUser = user
		foundPass = pass
		foundReq = req

		return true
	})

	req := newReq()
	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Basic "+base64.StdEncoding.EncodeToString([]byte("myuser:mypass"))))
	res := newRes()

	nextCalled := false
	next := func(res http.ResponseWriter, req *http.Request) {
		nextCalled = true
	}

	f(res, req, next)

	Expect(res.LastStatus).To(Equal(0))
	Expect(nextCalled).To(BeTrue())
	Expect(foundUser).To(Equal("myuser"))
	Expect(foundPass).To(Equal("mypass"))
	Expect(foundReq).To(BeIdenticalTo(req))
}

func (s *BasicSuite) TestBasicAuthInvalidAuth(t *testing.T) {
	f := BasicAuth("myrealm", map[string]string{
		"myuser": "mypass",
	})

	req := newReq()
	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Basic "+base64.StdEncoding.EncodeToString([]byte("notuser:notpass"))))
	res := newRes()

	nextCalled := false
	next := func(res http.ResponseWriter, req *http.Request) {
		nextCalled = true
	}

	f(res, req, next)

	Expect(res.LastStatus).To(Equal(http.StatusUnauthorized))
	Expect(res.Header().Get("WWW-Authenticate")).To(Equal(`Basic realm="myrealm"`))
	Expect(nextCalled).To(BeFalse())
}

func (s *BasicSuite) TestBasicAuthValidAuth(t *testing.T) {
	f := BasicAuth("myrealm", map[string]string{
		"myuser": "mypass",
	})

	req := newReq()
	req.Header.Set(
		"Authorization",
		fmt.Sprintf("Basic "+base64.StdEncoding.EncodeToString([]byte("myuser:mypass"))))
	res := newRes()

	nextCalled := false
	next := func(res http.ResponseWriter, req *http.Request) {
		nextCalled = true
	}

	f(res, req, next)

	Expect(res.LastStatus).To(Equal(0))
	Expect(nextCalled).To(BeTrue())
}
