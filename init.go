package sign

import "flag"

type SSLConFig struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
	CaFile   string `json:"caFile"`
}

func Init(host string) Context {
	return &context{
		host: host,
	}
}

func (c *context) InitSSL(ssl SSLConFig) Context {
	c.ssl.CertFile = flag.String("cert", ssl.CertFile, "A PEM eoncoded certificate file.")
	c.ssl.KeyFile = flag.String("key", ssl.KeyFile, "A PEM encoded private key file.")
	c.ssl.CaFile = flag.String("CA", ssl.CaFile, "A PEM eoncoded CA's certificate file.")
	return c
}
