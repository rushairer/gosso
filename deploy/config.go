package deploy

import (
	"log"

	"github.com/spf13/viper"
)

var EnvironmentConfig EnvironmentSettings

// 环境配置结构体
type EnvironmentSettings struct {
	Environments map[string]Environment `mapstructure:"environments"`
	Common       CommonConfig           `mapstructure:"common"`
}

type Environment struct {
	Description string           `mapstructure:"description"`
	App         AppEnvConfig     `mapstructure:"app"`
	Postgres    DBEnvConfig      `mapstructure:"postgres"`
	Redis       RedisEnvConfig   `mapstructure:"redis"`
	SMTP        SMTPEnvConfig    `mapstructure:"smtp"`
	Mailpit     MailpitEnvConfig `mapstructure:"mailpit"`
	Nginx       NginxEnvConfig   `mapstructure:"nginx"`
	Network     NetworkConfig    `mapstructure:"network"`
}

type AppEnvConfig struct {
	Port         int    `mapstructure:"port"`
	ExternalPort int    `mapstructure:"external_port"`
	Debug        bool   `mapstructure:"debug"`
	GinMode      string `mapstructure:"gin_mode"`
}

type DBEnvConfig struct {
	Port         int    `mapstructure:"port"`
	ExternalPort int    `mapstructure:"external_port"`
	Database     string `mapstructure:"database"`
	User         string `mapstructure:"user"`
	Password     string `mapstructure:"password"`
}

type RedisEnvConfig struct {
	Port         int `mapstructure:"port"`
	ExternalPort int `mapstructure:"external_port"`
	Database     int `mapstructure:"database"`
}

type SMTPEnvConfig struct {
	Port         int    `mapstructure:"port"`
	ExternalPort int    `mapstructure:"external_port"`
	Host         string `mapstructure:"host"`
}

type MailpitEnvConfig struct {
	WebPort         int `mapstructure:"web_port"`
	WebExternalPort int `mapstructure:"web_external_port"`
}

type NginxEnvConfig struct {
	HTTPPort  int `mapstructure:"http_port"`
	HTTPSPort int `mapstructure:"https_port"`
}

type NetworkConfig struct {
	Name   string `mapstructure:"name"`
	Subnet string `mapstructure:"subnet"`
}

type CommonConfig struct {
	Images  ImageConfig  `mapstructure:"images"`
	Volumes VolumeConfig `mapstructure:"volumes"`
}

type ImageConfig struct {
	Golang   string `mapstructure:"golang"`
	Postgres string `mapstructure:"postgres"`
	Redis    string `mapstructure:"redis"`
	Mailpit  string `mapstructure:"mailpit"`
	Nginx    string `mapstructure:"nginx"`
}

type VolumeConfig struct {
	PostgresDataSuffix string `mapstructure:"postgres_data_suffix"`
	RedisDataSuffix    string `mapstructure:"redis_data_suffix"`
	GoModCache         string `mapstructure:"go_mod_cache"`
}

// LoadEnvironmentConfig 加载环境配置
func LoadEnvironmentConfig(configPath string) error {
	envViper := viper.New()
	envViper.AddConfigPath(configPath)
	envViper.SetConfigName("environments")
	envViper.SetConfigType("yaml")

	if err := envViper.ReadInConfig(); err != nil {
		return err
	}

	if err := envViper.Unmarshal(&EnvironmentConfig); err != nil {
		return err
	}

	return nil
}

// GetEnvironment 获取指定环境的配置
func GetEnvironment(env string) (*Environment, bool) {
	if envConfig, exists := EnvironmentConfig.Environments[env]; exists {
		return &envConfig, true
	}
	return nil, false
}

// InitDeployConfig 初始化部署配置
func InitDeployConfig(deployPath string) error {
	if err := LoadEnvironmentConfig(deployPath); err != nil {
		log.Printf("Warning: failed to load environment config: %v", err)
		return err
	}
	return nil
}
