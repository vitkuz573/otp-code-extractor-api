// Minimal Go client for the OTP Code Extractor API.
// Build with: go build -o /tmp/otp-client examples/go_client.go
// Run with:   /tmp/otp-client

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const baseURL = "http://localhost:8000"

type fromUriReq struct {
	URI string `json:"uri"`
}

type fromSecretReq struct {
	Secret string `json:"secret"`
}

type otpResponse struct {
	Code             string  `json:"code"`
	Type             string  `json:"type"`
	Algorithm        string  `json:"algorithm"`
	Digits           int     `json:"digits"`
	Period           *int    `json:"period"`
	Counter          *int    `json:"counter"`
	Issuer           *string `json:"issuer"`
	Account          *string `json:"account"`
	Label            *string `json:"label"`
	RemainingSeconds *int    `json:"remaining_seconds"`
}

func postJSON(path string, body interface{}, out interface{}) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(baseURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(buf))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func fromURI(uri string) {
	var out otpResponse
	if err := postJSON("/v1/otp/from-uri", fromUriReq{URI: uri}, &out); err != nil {
		fmt.Println("from-uri error:", err)
		return
	}
	remaining := "<n/a>"
	if out.RemainingSeconds != nil {
		remaining = fmt.Sprintf("%ds", *out.RemainingSeconds)
	}
	issuer := "<none>"
	if out.Issuer != nil {
		issuer = *out.Issuer
	}
	fmt.Printf("URI -> code=%s issuer=%s remaining=%s\n", out.Code, issuer, remaining)
}

func fromSecret(secret string) {
	var out otpResponse
	if err := postJSON("/v1/otp/from-secret", fromSecretReq{Secret: secret}, &out); err != nil {
		fmt.Println("from-secret error:", err)
		return
	}
	fmt.Printf("secret -> code=%s digits=%d\n", out.Code, out.Digits)
}

func fromQRFile(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("qr skipped:", err)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	body := map[string]string{
		"image_base64": b64,
		"mime_type":    "image/png",
	}
	var out otpResponse
	if err := postJSON("/v1/otp/from-qr-base64", body, &out); err != nil {
		fmt.Println("from-qr error:", err)
		return
	}
	fmt.Printf("qr -> code=%s issuer=%v\n", out.Code, out.Issuer)
}

func main() {
	sample := "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME"
	fromURI(sample)
	fromSecret("JBSWY3DPEHPK3PXP")

	if len(os.Args) > 1 {
		fromQRFile(os.Args[1])
	}
}
