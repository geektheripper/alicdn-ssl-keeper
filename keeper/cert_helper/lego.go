package cert_helper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"

	aliapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/storage"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/registration"
)

type AcmeUser struct {
	Email        string
	Registration *registration.Resource
	privateKey   *ecdsa.PrivateKey
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}
func (u AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.privateKey
}

func getPrivateKey(storage storage.StorageService) (*ecdsa.PrivateKey, error) {
	privateKeyPem, err := storage.Read("private.key")
	if err != nil {
		return nil, err
	}

	if privateKeyPem != nil {
		block, _ := pem.Decode(privateKeyPem)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing private key")
		}

		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}

		return privateKey, nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC private key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %v", err)
	}

	privateKeyPem = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	err = storage.Write("private.key", privateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to save private key to storage: %v", err)
	}

	return privateKey, nil
}

func getRegistration(storage storage.StorageService, client *lego.Client) (*registration.Resource, error) {
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register: %v", err)
	}

	regBytes, err := json.Marshal(reg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration: %v", err)
	}

	err = storage.Write("registration.json", regBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to save registration to storage: %v", err)
	}

	return reg, nil
}

func InitLego(storage storage.StorageService, aliConfig *aliapi.Config, email string, caDirURL string) *lego.Client {
	// PrivateKey
	privateKey, err := getPrivateKey(storage)
	if err != nil {
		log.Fatalf("Error loading private key: %v", err)
	}

	// User
	u := &AcmeUser{Email: email, privateKey: privateKey}
	config := lego.NewConfig(u)
	config.CADirURL = caDirURL
	config.Certificate.KeyType = certcrypto.RSA2048

	// Client
	lego, err := lego.NewClient(config)
	if err != nil {
		log.Fatalf("Error creating lego client: %v", err)
	}

	// Registration
	reg, err := getRegistration(storage, lego)
	if err != nil {
		log.Fatalf("Error getting registration: %v", err)
	}

	u.Registration = reg

	// DNS Provider
	alidnsConfig := alidns.NewDefaultConfig()
	alidnsConfig.APIKey = *aliConfig.AccessKeyId
	alidnsConfig.SecretKey = *aliConfig.AccessKeySecret
	alidnsConfig.RegionID = *aliConfig.RegionId

	providerConifg, err := alidns.NewDNSProviderConfig(alidnsConfig)
	if err != nil {
		log.Fatalf("Error creating alidns provider config: %v", err)
	}

	err = lego.Challenge.SetDNS01Provider(providerConifg)
	if err != nil {
		log.Fatalf("Error setting DNS01 provider: %v", err)
	}

	return lego
}
