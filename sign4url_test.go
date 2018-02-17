package awsauth

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/smartystreets/assertions"
	"github.com/smartystreets/assertions/should"
)


func TestPresignBasic(t *testing.T) {

	// This is a canonical amazon example

	key := Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	ts, err := time.Parse(time.RFC1123, "Fri, 24 May 2013 00:00:00 GMT")
	if err != nil {
		panic(err)
	}

	ps := &Presign{
		Method:        "GET",
		SignedHeaders: make(http.Header),
		ContentSHA256: "",
		Date:          ts,
		Expires:       86400 * time.Second,
	}

	u := &url.URL{
		Host:   "examplebucket.s3.amazonaws.com",
		Path:   "/test.txt",
		Scheme: "https",
	}
	expSign := "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"

	_, sign := Sign4URL(ps, u, key)

	assert := assertions.New(t)
	assert.So(sign, should.Equal, expSign)
}

