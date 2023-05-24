package sign

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"

	requests "git.onespace.co.th/osgolib/http-requests"
	"github.com/labstack/echo/v4"
)

type (
	Context interface {
		Error() error
		InitSSL(SSLConFig) Context
		//ModePRD() Context
		//ModeUAT() Context
		Activate(BodyRequestSign, *ActivateCaResponse) Context
		ActivateByHost(string, BodyRequestSign, *ActivateCaResponse) Context
		JsonSigning(BodyRequestSign, *JsonSigningResponse) Context
		JsonSigningByHost(string, BodyRequestSign, *JsonSigningResponse) Context
		EncodeBase64(interface{}, *bytes.Buffer) Context
		JsonSigningSSL(BodyRequestSignSSL, *JsonSigningResponse) Context
		JsonSigningPDFSSL(string, BodyRequestPDFSignSSL, *JsonPDFSigningResponse) Context
		JsonSigningSSLDhp(BodyRequestSignSSL, *JsonSigningResponse) Context
		JsonSigningSSLByHost(string, BodyRequestSignSSL, *JsonSigningResponse) Context
		ListCredentials(BodyRequestSign, *JsoncredentialsListResponse) Context
	}
	context struct {
		ssl  FilePathSSL
		host string
		err  error
	}

	contextSpare struct {
		ssl  FilePathSSL
		host string
		err  error
	}
)

func (c *context) ActivateByHost(host string, request BodyRequestSign, response *ActivateCaResponse) Context {
	url := host + "/webservice/api/v2/credentials/authorize"
	body, _ := json.Marshal(ActivateBody{
		CredentialId: request.CredentialId,
	})

	headers := map[string]string{
		echo.HeaderContentType:   "application/json",
		echo.HeaderAuthorization: "Bearer " + request.Token,
	}
	param := requests.Params{
		URL:     url,
		BODY:    bytes.NewBuffer(body),
		HEADERS: headers,
		TIMEOUT: 5,
	}
	var res requests.Response
	if err := requests.Call().Post(param, &res).Error(); err != nil {
		c.err = err
		return c
	}
	if res.Code != 200 {
		c.err = fmt.Errorf(res.Status)
		return c
	}
	if err := json.Unmarshal(res.Result, &response); err != nil {
		c.err = err
		return c
	}
	c.err = nil
	return c
}

func (c *context) JsonSigningByHost(host string, sign BodyRequestSign, res *JsonSigningResponse) Context {
	body, _ := json.Marshal(sign.SignBody)
	param := requests.Params{
		URL:  host + "/webservice/api/v2/signing/jsonSigning",
		BODY: bytes.NewBuffer(body),
		HEADERS: map[string]string{
			echo.HeaderContentType: "application/json",
			"Authorization":        "Bearer " + sign.Token,
		},
		TIMEOUT: 5,
	}
	var response requests.Response
	if err := requests.Call().Post(param, &response).Error(); err != nil {
		c.err = err
		return c
	}
	if response.Code != 200 {
		c.err = fmt.Errorf(response.Status)
		return c
	}
	if err := json.Unmarshal(response.Result, &res); err != nil {
		c.err = err
		return c
	}
	c.err = nil
	return c
}

func (c *context) Error() error {
	if c.err != nil {
		return c.err
	}
	return nil
}

func (c *context) Activate(request BodyRequestSign, response *ActivateCaResponse) Context {
	url := c.host + "/webservice/api/v2/credentials/authorize"
	body, _ := json.Marshal(ActivateBody{
		CredentialId: request.CredentialId,
	})

	headers := map[string]string{
		echo.HeaderContentType:   "application/json",
		echo.HeaderAuthorization: "Bearer " + request.Token,
	}
	param := requests.Params{
		URL:     url,
		BODY:    bytes.NewBuffer(body),
		HEADERS: headers,
		TIMEOUT: 5,
	}
	var res requests.Response
	if err := requests.Call().Post(param, &res).Error(); err != nil {
		c.err = err
		return c
	}
	if res.Code != 200 {
		c.err = fmt.Errorf(res.Status)
		return c
	}
	if err := json.Unmarshal(res.Result, &response); err != nil {
		c.err = err
		return c
	}
	c.err = nil
	return c
}

func (c *context) JsonSigning(s BodyRequestSign, res *JsonSigningResponse) Context {
	body, _ := json.Marshal(s.SignBody)
	param := requests.Params{
		URL:  c.host + "/webservice/api/v2/signing/jsonSigning",
		BODY: bytes.NewBuffer(body),
		HEADERS: map[string]string{
			echo.HeaderContentType: "application/json",
			"Authorization":        "Bearer " + s.Token,
		},
		TIMEOUT: 5,
	}
	var response requests.Response
	if err := requests.Call().Post(param, &response).Error(); err != nil {
		c.err = err
		return c
	}
	if response.Code != 200 {
		c.err = fmt.Errorf(response.Status)
		return c
	}
	if err := json.Unmarshal(response.Result, &res); err != nil {
		c.err = err
		return c
	}
	c.err = nil
	return c
}

func (c *context) EncodeBase64(v interface{}, buf *bytes.Buffer) Context {
	encoder := b64.NewEncoder(b64.StdEncoding, buf)
	err := json.NewEncoder(encoder).Encode(v)
	if err != nil {
		c.err = err
		return c
	}
	err = encoder.Close()
	if err != nil {
		c.err = err
		return c
	}
	c.err = nil
	return c
}

func (c *context) JsonSigningSSL(bodySSL BodyRequestSignSSL, res *JsonSigningResponse) Context {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*c.ssl.CertFile, *c.ssl.KeyFile)
	if err != nil {
		c.err = err
		return c
	}

	caCertPool := x509.NewCertPool()

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	jsonData, err := json.Marshal(bodySSL)
	resp, err := client.Post(c.host+"/webservice/api/v2/signing/jsonSigning", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.err = err
		return c
	}

	var response Response
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	response.Code = resp.StatusCode
	response.Status = resp.Status
	response.Result = buf.Bytes()
	response.Header = resp.Header
	_ = resp.Body.Close()
	if response.Code != 200 {
		c.err = fmt.Errorf(response.Status)
		return c
	}
	if err := json.Unmarshal(response.Result, &res); err != nil {
		c.err = err
		return c
	}

	c.err = nil
	return c
}

func (c *context) JsonSigningSSLDhp(bodySSL BodyRequestSignSSL, res *JsonSigningResponse) Context {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*c.ssl.CertFile, *c.ssl.KeyFile)
	if err != nil {
		c.err = err
		return c
	}

	caCertPool := x509.NewCertPool()

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	jsonData, err := json.Marshal(bodySSL)
	resp, err := client.Post(c.host+"/webservice/api/v2/signing/dhpJsonSigning", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.err = err
		return c
	}

	var response Response
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	response.Code = resp.StatusCode
	response.Status = resp.Status
	response.Result = buf.Bytes()
	response.Header = resp.Header
	_ = resp.Body.Close()
	if response.Code != 200 {
		c.err = fmt.Errorf(response.Status)
		return c
	}
	if err := json.Unmarshal(response.Result, &res); err != nil {
		c.err = err
		return c
	}

	c.err = nil
	return c
}

func (c *context) JsonSigningSSLByHost(host string, bodySSL BodyRequestSignSSL, res *JsonSigningResponse) Context {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*c.ssl.CertFile, *c.ssl.KeyFile)
	if err != nil {
		c.err = err
		return c
	}

	caCertPool := x509.NewCertPool()

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	jsonData, err := json.Marshal(bodySSL)
	resp, err := client.Post(host+"/webservice/api/v2/signing/jsonSigning", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.err = err
		return c
	}

	var response Response
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	response.Code = resp.StatusCode
	response.Status = resp.Status
	response.Result = buf.Bytes()
	response.Header = resp.Header
	_ = resp.Body.Close()
	if response.Code != 200 {
		c.err = fmt.Errorf(response.Status)
		return c
	}
	if err := json.Unmarshal(response.Result, &res); err != nil {
		c.err = err
		return c
	}

	c.err = nil
	return c
}

func (c *context) JsonSigningPDFSSL(host string, ssl BodyRequestPDFSignSSL, res *JsonPDFSigningResponse) Context {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*c.ssl.CertFile, *c.ssl.KeyFile)
	if err != nil {
		c.err = err
		return c
	}

	caCertPool := x509.NewCertPool()

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	jsonData, err := json.Marshal(ssl)
	resp, err := client.Post(host+"/webservice/api/v2/signing/pdfSigning-V3", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.err = err
		return c
	}

	var response Response
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	response.Code = resp.StatusCode
	response.Status = resp.Status
	response.Result = buf.Bytes()
	response.Header = resp.Header
	_ = resp.Body.Close()
	if response.Code != 200 {
		c.err = fmt.Errorf(response.Status)
		return c
	}
	if err := json.Unmarshal(response.Result, &res); err != nil {
		c.err = err
		return c
	}

	c.err = nil
	return c
}

func (c *context) ListCredentials(v BodyRequestSign, res *JsoncredentialsListResponse) Context {
	param := requests.Params{
		URL: c.host + "/webservice/api/v2/credentials/list",
		HEADERS: map[string]string{
			echo.HeaderContentType: "application/json",
			"Authorization":        "Bearer " + v.Token,
		},
		TIMEOUT: 5,
	}
	var response requests.Response
	if err := requests.Call().Post(param, &response).Error(); err != nil {
		c.err = err
		return c
	}
	if response.Code != 200 {
		c.err = fmt.Errorf(response.Status)
		return c
	}

	if err := json.Unmarshal(response.Result, &res); err != nil {
		c.err = err
		return c
	}
	c.err = nil
	return c
}
