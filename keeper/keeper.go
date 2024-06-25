package keeper

import (
	"log"

	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/cert_helper"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/storage"
)

type Keeper struct {
	ServiceAgents []agent.ServiceCertAgent
	Storage       storage.StorageService
	CertManager   *cert_helper.CertManager
}

func (k *Keeper) Run() {
	for _, agent := range k.ServiceAgents {
		for certReq := range agent.CertRequest() {
			log.Printf("cert request from %s: %s", certReq.ServiceName(), certReq.CommonName())
			cert, err := k.CertManager.GetCertificate(certReq.CommonName())
			if err != nil {
				log.Printf("load cert failed: %v", err)
				continue
			}

			if err := certReq.SetCertificate(cert); err != nil {
				log.Printf("set cert failed: %v", err)
				continue
			}
		}
	}

	k.CertManager.CleanCasDuplicateCertificate()
	k.CertManager.CleanCasExpiredCertificate()
}
