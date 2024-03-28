package agent

import "github.com/geektheripper/alicdn-ssl-keeper/keeper/cert_helper"

type CertRequest interface {
	ServiceName() string
	CommonName() string
	SetCertificate(kc *cert_helper.Certificate) error
}

type ServiceCertAgent interface {
	CertRequest() <-chan CertRequest
}
