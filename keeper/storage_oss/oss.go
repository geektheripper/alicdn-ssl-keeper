package storage_oss

import (
	"bytes"
	"io/ioutil"
	"log"

	aliapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/aliyun/aliyun-oss-go-sdk/oss"
)

type OssBucketHelper struct {
	OssBucket    *oss.Bucket
	OssKeyPrefix string
}

func NewOssBucketHelper(aliConfig aliapi.Config, ossEndPoinets, ossBucket, ossKeyPrefix string) *OssBucketHelper {
	if ossEndPoinets == "" {
		ossEndPoinets = "oss-" + *aliConfig.RegionId + ".aliyuncs.com"
	}

	ossClient, err := oss.New(ossEndPoinets, *aliConfig.AccessKeyId, *aliConfig.AccessKeySecret)
	if err != nil {
		log.Fatalf("Error creating oss client: %v", err)
	}

	ossBucketClient, err := ossClient.Bucket(ossBucket)
	if err != nil {
		log.Fatalf("Error getting oss bucket: %v", err)
	}

	return &OssBucketHelper{
		OssBucket:    ossBucketClient,
		OssKeyPrefix: ossKeyPrefix,
	}
}

func (o *OssBucketHelper) Read(objectName string) ([]byte, error) {
	key := o.OssKeyPrefix + "/" + objectName
	body, err := o.OssBucket.GetObject(key)
	if err != nil {
		if ossErr, ok := err.(oss.ServiceError); ok && ossErr.Code == "NoSuchKey" {
			return nil, nil
		}
		return nil, err
	}

	data, err := ioutil.ReadAll(body)
	body.Close()

	return data, nil
}

func (o *OssBucketHelper) Write(objectName string, data []byte) error {
	key := o.OssKeyPrefix + "/" + objectName
	err := o.OssBucket.PutObject(key, bytes.NewReader(data))
	return err
}
