package agent_oss

import (
	"fmt"
	"log"
	"strconv"
	"time"

	aliapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/cert_helper"
	"github.com/geektheripper/alicdn-ssl-keeper/utils"
)

type OssCertRequest struct {
	ossClient *oss.Client
	region    string
	bucket    string
	domain    string
}

func (r *OssCertRequest) ServiceName() string {
	return "oss"
}

func (r *OssCertRequest) CommonName() string {
	return utils.DomainToCertCommonName(r.domain)
}

func (r *OssCertRequest) SetCertificate(cert *cert_helper.Certificate) error {
	err := r.ossClient.PutBucketCnameWithCertificate(r.bucket, oss.PutBucketCname{
		Cname: r.domain,
		CertificateConfiguration: &oss.CertificateConfiguration{
			CertId: strconv.FormatInt(cert.CasCertificateId, 10),
			Force:  true,
		},
	})

	if err != nil {
		return fmt.Errorf("set oss bucket cname failed: %v", err)
	}

	return nil
}

type OssCertAgent struct {
	AliConfig *aliapi.Config
}

func (a *OssCertAgent) NewOssClient(regionId string) *oss.Client {
	ossClient, err := oss.New("oss-"+regionId+".aliyuncs.com", *a.AliConfig.AccessKeyId, *a.AliConfig.AccessKeySecret)
	if err != nil {
		log.Fatalf("Error creating oss client: %v", err)
	}

	return ossClient
}

func NewOssCertAgent(aliConfig aliapi.Config) *OssCertAgent {
	return &OssCertAgent{AliConfig: &aliConfig}
}

func (a *OssCertAgent) scanCertRequest(bucket oss.BucketProperties) ([]*OssCertRequest, error) {
	log.Printf("scan domains for bucket %s", bucket.Name)

	ossClient := a.NewOssClient(bucket.Region)
	result, err := ossClient.ListBucketCname(bucket.Name)
	if err != nil {
		return nil, err
	}

	requestList := make([]*OssCertRequest, 0)

	for _, cname := range result.Cname {
		if cname.Certificate.CertId != "" {
			expireTime, _ := time.Parse("", cname.Certificate.ValidEndDate)
			if expireTime.After(time.Now().AddDate(0, 0, 7)) {
				continue
			}
		}

		requestList = append(requestList, &OssCertRequest{
			ossClient: ossClient,
			region:    bucket.Region,
			bucket:    bucket.Name,
			domain:    cname.Domain,
		})
	}

	return requestList, nil
}

func (a *OssCertAgent) CertRequest() <-chan agent.CertRequest {
	ch := make(chan agent.CertRequest)

	go func() {
		defer close(ch)
		ossClient := a.NewOssClient(*a.AliConfig.RegionId)

		nextMarker := ""
		for {
			result, err := ossClient.ListBuckets(oss.Marker(nextMarker))
			if err != nil {
				log.Fatalf("Error listing oss buckets: %v", err)
			}

			for _, bucket := range result.Buckets {
				requestList, err := a.scanCertRequest(bucket)
				if err != nil {
					log.Fatalf("Error scanning cert request: %v", err)
				}

				for _, req := range requestList {
					ch <- req
				}
			}

			if !result.IsTruncated {
				break
			}

			nextMarker = result.NextMarker
		}

	}()

	return ch
}
