package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"

	aliapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent_cdn"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent_live"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/agent_oss"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/cert_helper"
	"github.com/geektheripper/alicdn-ssl-keeper/keeper/storage_oss"
	"github.com/go-acme/lego/v4/lego"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "ssl-keeper",
	Short: "auto update certificates for alibaba cloud cdn",
	Run: func(cmd *cobra.Command, args []string) {
		keeper := &keeper.Keeper{}

		config := &aliapi.Config{
			RegionId:        tea.String(viper.GetString("region-id")),
			AccessKeyId:     tea.String(viper.GetString("access-key-id")),
			AccessKeySecret: tea.String(viper.GetString("access-key-secret")),
		}

		// Services
		keeper.ServiceAgents = []agent.ServiceCertAgent{
			agent_cdn.NewCdnCertAgent(
				*config,
				viper.GetString("cdn-tag"),
				viper.GetString("cdn-resource-group"),
			),
			agent_oss.NewOssCertAgent(*config),
			agent_live.NewLiveCertAgent(*config),
		}

		// Storage
		keeper.Storage = storage_oss.NewOssBucketHelper(
			*config,
			viper.GetString("oss-endpoints"),
			viper.GetString("oss-bucket"),
			viper.GetString("oss-key-prefix"),
		)

		// CertManager
		legoClient := cert_helper.InitLego(
			keeper.Storage,
			config,
			viper.GetString("acme-email"),
			viper.GetString("acme-directory-url"),
		)
		keeper.CertManager = cert_helper.NewCertManager(config, legoClient, keeper.Storage)

		keeper.Run()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	// ACME
	rootCmd.Flags().String("acme-directory-url", lego.LEDirectoryProduction, "acme directory url")
	rootCmd.Flags().String("acme-email", "", "acme email")

	// Aliyun Creds
	rootCmd.Flags().String("region-id", "cn-hangzhou", "aliyun region id")
	rootCmd.Flags().String("access-key-id", "", "aliyun access key id")
	rootCmd.Flags().String("access-key-secret", "", "aliyun access key secret")

	// Filters
	rootCmd.Flags().String("cdn-tag", "", "filter domains by tag in key[:value] format")
	rootCmd.Flags().String("cdn-resource-group", "", "filter domains by resource group id")

	// OSS
	rootCmd.Flags().String("oss-endpoints", "", "oss endpoints, default to oss-{region-id}.aliyuncs.com")
	rootCmd.Flags().String("oss-bucket", "", "oss bucket")
	rootCmd.Flags().String("oss-key-prefix", "ssl-keeper", "oss key prefix")

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.BindPFlags(rootCmd.Flags())

	// https://github.com/aliyun/aliyun-cli/blob/master/README.md#supported-environment-variables
	viper.BindEnv("region-id", "ALIBABACLOUD_REGION_ID", "ALICLOUD_REGION_ID", "REGION")
	viper.BindEnv("access-key-id", "Ali_Key", "ALIBABACLOUD_ACCESS_KEY_ID", "ALICLOUD_ACCESS_KEY_ID")
	viper.BindEnv("access-key-secret", "Ali_Secret", "ALIBABACLOUD_ACCESS_KEY_SECRET", "ALICLOUD_ACCESS_KEY_SECRET")
}
