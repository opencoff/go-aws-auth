// sign4url.go - AWS V4 Presigned URL
package awsauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"time"
	"sort"
	"strings"
	"strconv"
)

// Presign provides information necessary to pre-sign URLs with
// version 4 scheme
type Presign struct {
	Method          string
	SignedHeaders   http.Header
	ContentSHA256   string
	Date            time.Time
	Expires         time.Duration
}

// Sign4URL pre-signs a URL with signature version 4
func Sign4URL(ps *Presign, u *url.URL, c ...Credentials) (*url.URL, string) {
	keys := chooseKeys(c)

	sh := make([]string, 0, len(ps.SignedHeaders))
	ok := false
	for h := range ps.SignedHeaders {
		z := strings.ToLower(h)
		if z == "host" {
			ok = true
		}
		sh = append(sh, z)
	}

	if !ok {
		sh = append(sh, "host")
		ps.SignedHeaders["Host"] = []string{u.Host}
	}

	sort.Strings(sh)

	ts := ps.Date.Format(timeFormatV4)
	qv := make(url.Values)
	qv.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	qv.Set("X-Amz-SignedHeaders", strings.Join(sh, ";"))
	qv.Set("X-Amz-Date", ts)
	qv.Set("X-Amz-Expires", strconv.Itoa(int(ps.Expires/time.Second)))
	qv.Set("X-Amz-Credential", creds(u.Host, keys, ps.Date))

	cksum := "UNSIGNED-PAYLOAD"
	if ps.ContentSHA256 != "" {
		qv.Set("X-Amz-Content-Sha256", ps.ContentSHA256)
		cksum = ps.ContentSHA256
	}

	oldv := u.Query()
	for k, v := range oldv {
		switch k {
		case "X-Amz-Algorithm", "X-Amz-SignedHeaders", "X-Amz-Date",
			"X-Amz-Expires", "X-Amz-Credential", "X-Amz-Signature":
			continue

		default:
			qv[k] = v
		}
	}

	presign := canonReq(ps, u.Path, qv, sh, cksum)
	signStr := signString(ts, scope(u.Host, ps.Date), presign)
	signKey := signingKey(u.Host, ps.Date.Format(dateFormatV4), keys.SecretAccessKey)
	sign    := calcSignature(signKey, signStr)
	qv.Set("X-Amz-Signature", sign)

	/*
	fmt.Printf("canon Req:\n%s\n", presign)
	fmt.Printf("str to sign:\n%s\n", signStr)
	fmt.Printf("signing key:\n%x\n", signKey)
	fmt.Printf("signature: %s\n", sign)
	*/

	u2 := &url.URL{
		Scheme:   u.Scheme,
		User:     u.User,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: qv.Encode(),
	}

	return u2, sign
}

func creds(h string, key Credentials, d time.Time) string {
	return fmt.Sprintf("%s/%s", key.AccessKeyID, scope(h, d))
}

func scope(h string, d time.Time) string {
	svc, reg := serviceAndRegion(h)
	date := d.Format(dateFormatV4)
	return fmt.Sprintf("%s/%s/%s/aws4_request", date, reg, svc)
}

func canonReq(ps *Presign, path string, qv url.Values, sh []string, cksum string) string {
	var x string = strings.Replace(qv.Encode(), "+", "%20", -1)
	var b bytes.Buffer

	b.WriteString(ps.Method)
	b.WriteByte('\n')
	b.WriteString(path) // XXX Do we encode here or not?
	b.WriteByte('\n')
	b.WriteString(x)
	b.WriteByte('\n')
	b.WriteString(canonHeaders(ps.SignedHeaders, sh))
	b.WriteByte('\n')
	b.WriteString(strings.Join(sh, ";"))
	b.WriteByte('\n')
	b.WriteString(cksum)
	return b.String()
}

func canonHeaders(h http.Header, sh []string) string {
	var b bytes.Buffer

	for _, kl := range sh {
		k := http.CanonicalHeaderKey(kl)
		vx := h[k]
		b.WriteString(kl)
		b.WriteByte(':')
		for i, v := range vx {
			if i > 0 {
				b.WriteByte(',')
			}
			z := strings.Fields(v)
			b.WriteString(strings.Join(z, " "))
		}
		b.WriteByte('\n')
	}
	return b.String()
}


// string to be signed
func signString(ts, creds, presign string) string {
	var b bytes.Buffer
	b.WriteString("AWS4-HMAC-SHA256")
	b.WriteByte('\n')
	b.WriteString(ts)
	b.WriteByte('\n')
	b.WriteString(creds)
	b.WriteByte('\n')

	c := sha256.Sum256([]byte(presign))
	b.WriteString(hex.EncodeToString(c[:]))
	return b.String()
}

func signingKey(h, date, secret string) []byte {
	svc, reg := serviceAndRegion(h)
	dk := qhmac([]byte("AWS4"+secret), []byte(date))
	rk := qhmac(dk, []byte(reg))
	sk := qhmac(rk, []byte(svc))
	fk := qhmac(sk, []byte("aws4_request"))
	return fk
}

// calculate final AWS4 signature
func calcSignature(key []byte, s string) string {
	h := qhmac(key, []byte(s))
	return hex.EncodeToString(h)
}

func qhmac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// vim: noexpandtab:sw=8:ts=8:tw=98:
