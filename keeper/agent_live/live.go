package agent_live

import (
	"fmt"
	"log"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	live "github.com/aliyun/alibaba-cloud-sdk-go/services/live"

	aliapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/cert_helper"
	"github.com/geektheripper/alicdn-ssl-keeper/utils"
)

type LiveCertRequest struct {
	liveClient *live.Client
	domain     *live.PageData
}

func (r *LiveCertRequest) ServiceName() string {
	return "live"
}

func (r *LiveCertRequest) CommonName() string {
	return utils.DomainToCertCommonName(r.domain.DomainName)
}

func (r *LiveCertRequest) SetCertificate(cert *cert_helper.Certificate) error {
	request := live.CreateSetLiveDomainCertificateRequest()
	request.Scheme = "https"
	request.DomainName = r.domain.DomainName
	request.CertName = cert.CasName()
	request.CertType = "cas"
	request.SSLProtocol = "on"
	request.ForceSet = "1"

	_, err := r.liveClient.SetLiveDomainCertificate(request)

	if err != nil {
		return fmt.Errorf("set live domain ssl certificate failed: %v", err)
	}

	return nil
}

type LiveCertAgent struct {
	LiveClient *live.Client
}

func NewLiveCertAgent(aliConfig aliapi.Config) *LiveCertAgent {
	config := sdk.NewConfig()
	credential := credentials.NewAccessKeyCredential(*aliConfig.AccessKeyId, *aliConfig.AccessKeySecret)
	liveClient, err := live.NewClientWithOptions("cn-hangzhou", config, credential)
	if err != nil {
		log.Fatalf("Error creating live client: %v", err)
	}

	return &LiveCertAgent{LiveClient: liveClient}
}

func (a *LiveCertAgent) listDomains(pageNumber int) ([]*live.PageData, bool, error) {
	request := live.CreateDescribeLiveUserDomainsRequest()
	request.Scheme = "https"
	request.PageSize = requests.NewInteger(50)
	request.PageNumber = requests.NewInteger(pageNumber)

	response, err := a.LiveClient.DescribeLiveUserDomains(request)
	if err != nil {
		return nil, false, fmt.Errorf("describe user domains failed: %v", err)
	}

	results := []*live.PageData{}

loopdomain:
	for _, domain := range response.Domains.PageData {
		log.Printf("Checking domain %s", domain.DomainName)
		request := live.CreateDescribeLiveDomainCertificateInfoRequest()
		request.Scheme = "https"
		request.DomainName = domain.DomainName

		response, err := a.LiveClient.DescribeLiveDomainCertificateInfo(request)
		if err != nil {
			return nil, false, fmt.Errorf("describe live domain certificate info failed: %v", err)
		}

		for _, certInfo := range response.CertInfos.CertInfo {
			expireTime, _ := time.Parse("", certInfo.CertExpireTime)
			if expireTime.After(time.Now().AddDate(0, 0, 7)) {
				continue loopdomain
			}
		}

		_domain := domain
		results = append(results, &_domain)
	}

	listEnd := (response.TotalCount < response.PageSize*response.PageNumber)
	return results, listEnd, nil
}

func (a *LiveCertAgent) CertRequest() <-chan agent.CertRequest {
	ch := make(chan agent.CertRequest)

	go func() {
		defer close(ch)

		pageNumber := int(1)

		for {
			var err error
			domains, listEnd, err := a.listDomains(pageNumber)
			if err != nil {
				log.Fatalf("list domains failed: %v", err)
			}

			for _, domain := range domains {
				if err != nil {
					log.Fatalf("check domain expired failed: %v", err)
				}

				ch <- &LiveCertRequest{
					liveClient: a.LiveClient,
					domain:     domain,
				}
			}

			if listEnd {
				break
			}

			pageNumber++
		}
	}()

	return ch
}
