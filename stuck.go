package sign

import (
	"net/http"
)

type ActivateCaResponse struct {
	ExpiresIn int    `json:"expiresIn"`
	Sad       string `json:"sad"`
}

type JsonSigningResponse struct {
	ExpiresIn       int    `json:"responseCode"`
	ResponseMessage string `json:"responseMessage"`
	JwsData         string `json:"jwsData"`
}

type JsonPDFSigningResponse struct {
	ResponseCode    int    `json:"responseCode"`
	ResponseMessage string `json:"responseMessage"`
	PdfData         string `json:"pdfData"`
}

type ActivateBody struct {
	CredentialId string `json:"credentialId"`
}

type JsonSigningBody struct {
	SadData          string `json:"sadData"`
	DocumentId       string `json:"documentId"`
	BcResponseURL    string `json:"bcResponseURL"`
	SignatureContent string `json:"signatureContent"`
}

type BodyRequestSign struct {
	Token        string
	CredentialId string
	SignBody     JsonSigningBody
}

type BodyRequestSignSSL struct {
	CadData          string `json:"cadData"`
	DocumentId       string `json:"documentId"`
	BcResponseURL    string `json:"bcResponseURL"`
	SignatureContent string `json:"signatureContent"`
}

type BodyRequestPDFSignSSL struct {
	PdfData                   string `json:"pdfData"`
	SadData                   string `json:"sadData"`
	CadData                   string `json:"cadData"`
	Reason                    string `json:"reason"`
	Location                  string `json:"location"`
	CertifyLevel              string `json:"certifyLevel"`
	HashAlgorithm             string `json:"hashAlgorithm"`
	OverwriteOriginal         bool   `json:"overwriteOriginal"`
	VisibleSignature          string `json:"visibleSignature"`
	VisibleSignaturePage      int    `json:"visibleSignaturePage"`
	VisibleSignatureRectangle string `json:"visibleSignatureRectangle"`
	VisibleSignatureImagePath string `json:"visibleSignatureImagePath"`
}

type FilePathSSL struct {
	CertFile *string `json:"certFile"`
	KeyFile  *string `json:"keyFile"`
	CaFile   *string `json:"caFile"`
}

type Response struct {
	Code   int
	Status string
	Header http.Header
	Result []byte
}

type JsoncredentialsListResponse struct {
	TotalResult int               `json:"totalResult"`
	Credentials []JsonCredentials `json:"credentials"`
}

type JsonCredentials struct {
	CredentialID  string      `json:"credentialId"`
	Name          string      `json:"name"`
	Status        interface{} `json:"status"`
	CertificateDn string      `json:"certificateDn"`
	AuthInfo      string      `json:"authInfo"`
	ExpiredDate   string      `json:"expiredDate"`
	LtvInfo       interface{} `json:"ltvInfo"`
}
