package cert_helper

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/samber/lo"

	cas "github.com/alibabacloud-go/cas-20200407/v2/client"
	aliapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"

	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/storage"
)

type CertManager struct {
	lego    *lego.Client
	cas     *cas.Client
	storage storage.StorageService
	cache   map[string]*Certificate
}

func NewCertManager(config *aliapi.Config, lego *lego.Client, storage storage.StorageService) *CertManager {
	config.Endpoint = tea.String("cas.aliyuncs.com")
	casClient, err := cas.NewClient(config)

	if err != nil {
		log.Fatalf("Error creating cas client: %v", err)
	}

	return &CertManager{
		lego:    lego,
		cas:     casClient,
		storage: storage,
		cache:   make(map[string]*Certificate),
	}
}

func (m *CertManager) GetCertificateFromStorage(commonName string) (*Certificate, error) {
	var cert *Certificate = &Certificate{
		CommonName: commonName,
	}
	var err error

	cert.PrivateKey, err = m.storage.Read(commonName + "/key.pem")
	if err != nil {
		return nil, err
	}

	cert.Certificate, err = m.storage.Read(commonName + "/cert.pem")
	if err != nil {
		return nil, err
	}

	cert.IssuerCertificate, err = m.storage.Read(commonName + "/chain.pem")
	if err != nil {
		return nil, err
	}

	if cert.Certificate != nil {
		block, _ := pem.Decode(cert.Certificate)
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		if int(x509Cert.NotAfter.Sub(time.Now()).Hours()/24) > 7 {
			return cert, nil
		}
	}

	request := certificate.ObtainRequest{Domains: []string{commonName}}

	if cert.PrivateKey != nil {
		request.PrivateKey = cert.PrivateKey
	}

	certRes, err := m.lego.Certificate.Obtain(request)
	if err != nil {
		return nil, nil
	}

	cert.PrivateKey = certRes.PrivateKey
	cert.Certificate = certRes.Certificate
	cert.IssuerCertificate = certRes.IssuerCertificate
	cert.Updated = true

	if err := m.storage.Write(commonName+"/key.pem", cert.PrivateKey); err != nil {
		return nil, err
	}
	if err := m.storage.Write(commonName+"/cert.pem", cert.Certificate); err != nil {
		return nil, err
	}
	if err := m.storage.Write(commonName+"/chain.pem", cert.IssuerCertificate); err != nil {
		return nil, err
	}
	if err := m.storage.Write(commonName+"/fullchain.pem", append(cert.Certificate, cert.IssuerCertificate...)); err != nil {
		return nil, err
	}

	return cert, nil
}

func (m *CertManager) SearchAvailableCertificateFromCas(commonName string) (*Certificate, error) {
	resp, err := m.cas.ListUserCertificateOrderWithOptions(&cas.ListUserCertificateOrderRequest{
		OrderType: tea.String("UPLOAD"),
		Keyword:   tea.String(commonName),
		Status:    tea.String("ISSUED"),
	}, &util.RuntimeOptions{})

	if err != nil {
		return nil, err
	}

	for _, certOrder := range resp.Body.CertificateOrderList {
		domains := strings.Split(*certOrder.Sans, ",")
		if lo.Contains(domains, commonName) {
			cert := &Certificate{
				CommonName:       commonName,
				CasCertificateId: *certOrder.CertificateId,
				casName:          *certOrder.Name,
			}
			return cert, nil
		}
	}

	return nil, nil
}

func (m *CertManager) UploadCertificateToCas(cert *Certificate) error {
	result, err := m.cas.UploadUserCertificate(&cas.UploadUserCertificateRequest{
		Name: tea.String(cert.CasName()),
		Cert: tea.String(string(cert.Certificate)),
		Key:  tea.String(string(cert.PrivateKey)),
	})

	if err != nil {
		return nil
	}

	cert.SetCasCertificateId(*result.Body.CertId)

	return err
}

func (m *CertManager) GetCertificate(commonName string) (*Certificate, error) {
	if cert, ok := m.cache[commonName]; ok {
		return cert, nil
	}

	var cert *Certificate

	cert, err := m.SearchAvailableCertificateFromCas(commonName)
	if err != nil {
		return nil, err
	}

	if cert == nil {
		cert, err = m.GetCertificateFromStorage(commonName)
		if err != nil {
			return nil, err
		}

		err = m.UploadCertificateToCas(cert)
		if err != nil {
			return nil, err
		}
	}

	m.cache[commonName] = cert

	return cert, nil
}

func (m *CertManager) CleanCasExpiredCertificate() {
	resp, err := m.cas.ListUserCertificateOrderWithOptions(&cas.ListUserCertificateOrderRequest{
		OrderType: tea.String("UPLOAD"),
		Status:    tea.String("EXPIRED"),
	}, &util.RuntimeOptions{})

	if err != nil {
		return
	}

	for _, certOrder := range resp.Body.CertificateOrderList {
		if !strings.HasPrefix(*certOrder.Name, "sslkeeper-") {
			continue
		}

		m.cas.DeleteUserCertificate(&cas.DeleteUserCertificateRequest{
			CertId: tea.Int64(*certOrder.CertificateId),
		})

		log.Printf("delete expired certificate %s (%s)", *certOrder.Name, *certOrder.Sans)
	}
}
