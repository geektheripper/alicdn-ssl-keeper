package cert_helper

import (
	"crypto/x509"
	"strings"

	"github.com/geektheripper/alicdn-ssl-keeper/utils"
)

type Certificate struct {
	CommonName       string
	CasCertificateId int64

	PrivateKey        []byte
	Certificate       []byte
	IssuerCertificate []byte

	Updated bool

	casName  string
	x509Cert *x509.Certificate
}

func (c *Certificate) X509Certificate() *x509.Certificate {
	if c.x509Cert != nil {
		return c.x509Cert
	}

	x509Cert, _ := utils.ParseCertificate(c.Certificate)

	c.x509Cert = x509Cert
	return c.x509Cert
}

func (c *Certificate) SetCasName(name string) {
	c.casName = name
}

func (c *Certificate) SetCasCertificateId(id int64) {
	c.CasCertificateId = id
}

func (c *Certificate) CasName() string {
	if c.casName == "" {
		c.casName = "sslkeeper-" +
			strings.ReplaceAll(strings.Replace(c.CommonName, "*.", "", 1), ".", "_") +
			"-" +
			c.X509Certificate().NotAfter.Format("20060102") +
			utils.ShortMd5(string(c.Certificate))
	}
	return c.casName
}

func (c *Certificate) MatchDomain(domain string) bool {
	if domain == c.CommonName {
		return true
	}

	if strings.HasPrefix(c.CommonName, "*.") &&
		strings.HasSuffix(domain, c.CommonName[1:]) &&
		strings.Count(domain, ".") == strings.Count(c.CommonName, ".") {
		return true
	}

	return false
}
