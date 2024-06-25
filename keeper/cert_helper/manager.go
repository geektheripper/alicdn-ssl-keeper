package cert_helper

import (
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
	"github.com/geektheripper/alicdn-ssl-keeper/utils"
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
		x509Cert, err := utils.ParseCertificate(cert.Certificate)
		if err != nil {
			return nil, err
		}

		if int(x509Cert.NotAfter.Sub(time.Now()).Hours()/24) > 7 {
			return cert, nil
		}
	}

	request := certificate.ObtainRequest{Domains: []string{commonName}}

	if cert.PrivateKey != nil {
		request.PrivateKey, err = utils.ParseRSAKey(cert.PrivateKey)
		if err != nil {
			return nil, err
		}
	}

	certRes, err := m.lego.Certificate.Obtain(request)
	if err != nil {
		return nil, err
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
		if !lo.Contains(domains, commonName) {
			continue
		}

		certDetailResp, err := m.cas.GetUserCertificateDetail(&cas.GetUserCertificateDetailRequest{CertId: certOrder.CertificateId})
		if err != nil {
			return nil, err
		}

		cert, err := utils.ParseCertificate([]byte(*certDetailResp.Body.Cert))
		if err != nil {
			return nil, err
		}

		if int(cert.NotAfter.Sub(time.Now()).Hours()/24) > 7 {
			return &Certificate{
				CommonName:       commonName,
				CasCertificateId: *certOrder.CertificateId,
				casName:          *certOrder.Name,
			}, nil
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

func (m *CertManager) tryLogAndDeleteCertificate(cert *cas.ListUserCertificateOrderResponseBodyCertificateOrderList, reason string) {
	log.Printf("delete certificate %s (%d): %s", *cert.Name, *cert.CertificateId, reason)
	_, err := m.cas.DeleteUserCertificate(&cas.DeleteUserCertificateRequest{CertId: cert.CertificateId})
	if err != nil {
		log.Printf("delete certificate %d failed: %v", *cert.CertificateId, err)
	}
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

		m.tryLogAndDeleteCertificate(certOrder, "expired")
	}
}

func (m *CertManager) CleanCasDuplicateCertificate() {
	resp, err := m.cas.ListUserCertificateOrderWithOptions(&cas.ListUserCertificateOrderRequest{
		OrderType: tea.String("UPLOAD"),
	}, &util.RuntimeOptions{})

	if err != nil {
		return
	}

	type CertInfo struct {
		Cert *cas.ListUserCertificateOrderResponseBodyCertificateOrderList
		Exp  int64
	}

	certMap := make(map[string]*CertInfo)

	for _, certOrder := range resp.Body.CertificateOrderList {
		if !strings.HasPrefix(*certOrder.Name, "sslkeeper-") {
			continue
		}

		certResp, err := m.cas.GetUserCertificateDetail(&cas.GetUserCertificateDetailRequest{CertId: certOrder.CertificateId})
		if err != nil {
			log.Printf("get certificate detail for %d failed: %v", *certOrder.CertificateId, err)
			continue
		}

		cert, err := utils.ParseCertificate([]byte(*certResp.Body.Cert))
		if err != nil {
			log.Printf("parse certificate for %d failed: %v", *certOrder.CertificateId, err)
			continue
		}

		current := &CertInfo{
			Cert: certOrder,
			Exp:  cert.NotAfter.Unix(),
		}

		if _, ok := certMap[*certOrder.CommonName]; !ok {
			certMap[*certOrder.CommonName] = current
		} else {
			recorded := certMap[*certOrder.CommonName]
			if current.Exp < recorded.Exp {
				m.tryLogAndDeleteCertificate(current.Cert, "duplicated")
			} else {
				m.tryLogAndDeleteCertificate(recorded.Cert, "duplicated")
				certMap[*certOrder.CommonName] = current
			}
		}
	}
}
