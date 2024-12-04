package config

import (
	"fmt"
	"github.com/spf13/viper"
)

type Config struct {
	PostgresHost     string
	PostgresPort     string
	PostgresUser     string
	PostgresPassword string
	PostgresSSL      string
	PostgresDB       string
	JWTSecretKey     string
	ServerPort       string
	ServerAddress    string
	SMTPFrom         string
	SMTPUsername     string
	SMTPPass         string
	SMTPHost         string
	SMTPPort         int
}

func LoadConfig() (*Config, error) {
	viper.SetConfigFile("./.env")
	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	config := &Config{
		PostgresHost:     viper.GetString("POSTGRES_HOST"),
		PostgresPort:     viper.GetString("POSTGRES_PORT"),
		PostgresUser:     viper.GetString("POSTGRES_USER"),
		PostgresPassword: viper.GetString("POSTGRES_PASSWORD"),
		PostgresSSL:      viper.GetString("POSTGRES_SSL"),
		PostgresDB:       viper.GetString("POSTGRES_DB"),
		JWTSecretKey:     viper.GetString("JWT_SECRET_KEY"),
		ServerPort:       viper.GetString("SERVER_PORT"),
		ServerAddress:    viper.GetString("SERVER_ADDRESS"),
		SMTPFrom:         viper.GetString("SMTP_FROM"),
		SMTPUsername:     viper.GetString("SMTP_FROM"),
		SMTPPass:         viper.GetString("SMTP_PASS"),
		SMTPHost:         viper.GetString("SMTP_HOST"),
		SMTPPort:         viper.GetInt("SMTP_PORT"),
	}
	return config, nil
}

func (cfg *Config) PostgresURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresDB, cfg.PostgresSSL)
}
