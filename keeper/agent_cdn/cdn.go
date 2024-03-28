package agent_cdn

import (
	"fmt"
	"log"
	"strings"
	"time"

	cdn "github.com/alibabacloud-go/cdn-20180510/v4/client"
	aliapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/cert_helper"
	"github.com/geektheripper/alicdn-ssl-keeper/utils"
)

type CdnCertRequest struct {
	cdnClient *cdn.Client
	domain    *cdn.DescribeUserDomainsResponseBodyDomainsPageData
}

func (r *CdnCertRequest) ServiceName() string {
	return "cdn"
}

func (r *CdnCertRequest) CommonName() string {
	return utils.DomainToCertCommonName(*r.domain.DomainName)
}

func (r *CdnCertRequest) SetCertificate(cert *cert_helper.Certificate) error {
	_, err := r.cdnClient.SetCdnDomainSSLCertificate(&cdn.SetCdnDomainSSLCertificateRequest{
		DomainName:  tea.String(*r.domain.DomainName),
		SSLProtocol: tea.String("on"),
		CertType:    tea.String("cas"),
		CertName:    tea.String(cert.CasName()),
		CertId:      &cert.CasCertificateId,
	})

	if err != nil {
		return fmt.Errorf("set cdn domain ssl certificate failed: %v", err)
	}

	return nil
}

type CdnCertAgent struct {
	CdnClient        *cdn.Client
	CdnTag           string
	CdnResourceGroup string
}

func NewCdnCertAgent(aliConfig aliapi.Config, cdnTag, cdnResourceGroup string) *CdnCertAgent {
	aliConfig.Endpoint = tea.String("cdn.aliyuncs.com")
	cdnClient, err := cdn.NewClient(&aliConfig)
	if err != nil {
		log.Fatalf("Error creating cdn client: %v", err)
	}

	return &CdnCertAgent{
		CdnClient:        cdnClient,
		CdnTag:           cdnTag,
		CdnResourceGroup: cdnResourceGroup,
	}
}

func (a *CdnCertAgent) isDomainExpired(domain *string) (bool, error) {
	resp, err := a.CdnClient.DescribeDomainCertificateInfo(&cdn.DescribeDomainCertificateInfoRequest{
		DomainName: domain,
	})
	if err != nil {
		return false, fmt.Errorf("describe domain certificate info failed: %v", err)
	}

	if resp.Body.CertInfos.CertInfo != nil {
		for _, certInfo := range resp.Body.CertInfos.CertInfo {
			if *certInfo.CertExpireTime == "" {
				continue
			}

			expireTime, _ := time.Parse(time.RFC3339, *certInfo.CertExpireTime)

			if expireTime.After(time.Now().AddDate(0, 0, 7)) {
				log.Printf("cert for %s is not expired", *domain)
				return false, nil
			}
		}
	}

	return true, nil
}

func (a *CdnCertAgent) listDomains(pageNumber int32) ([]*cdn.DescribeUserDomainsResponseBodyDomainsPageData, bool, error) {
	request := &cdn.DescribeUserDomainsRequest{
		PageSize:   tea.Int32(500),
		PageNumber: tea.Int32(pageNumber),
	}

	if a.CdnTag != "" {
		kv := strings.Split(a.CdnTag, ":")
		if kv[0] == "" {
			return nil, false, fmt.Errorf("illegal tag format: %s", a.CdnTag)
		}

		tag := cdn.DescribeUserDomainsRequestTag{}
		tag.Key = tea.String(kv[0])
		if len(kv) > 1 && kv[1] != "" {
			tag.Value = tea.String(kv[1])
		}

		request.Tag = []*cdn.DescribeUserDomainsRequestTag{&tag}
	}

	if a.CdnResourceGroup != "" {
		request.ResourceGroupId = tea.String(a.CdnResourceGroup)
	}

	response, err := a.CdnClient.DescribeUserDomains(request)
	if err != nil {
		return nil, false, fmt.Errorf("list domains failed: %v", err)
	}

	body := response.Body

	listEnd := (*body.TotalCount < *body.PageSize**body.PageNumber)
	return body.Domains.PageData, listEnd, nil
}

func (a *CdnCertAgent) CertRequest() <-chan agent.CertRequest {
	ch := make(chan agent.CertRequest)

	go func() {
		defer close(ch)

		pageNumber := int32(1)

		for {
			var err error
			domains, listEnd, err := a.listDomains(pageNumber)
			if err != nil {
				log.Fatalf("list domains failed: %v", err)
			}

			for _, domain := range domains {
				expired, err := a.isDomainExpired(domain.DomainName)
				if err != nil {
					log.Fatalf("check domain expired failed: %v", err)
				}

				if !expired {
					continue
				}

				ch <- &CdnCertRequest{
					cdnClient: a.CdnClient,
					domain:    domain,
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
