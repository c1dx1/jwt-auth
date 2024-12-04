package packages

import (
	"fmt"
	"gopkg.in/gomail.v2"
	"jwt-auth/internal/models"
	"log"
)

type Email struct {
	from      string
	username  string
	password  string
	smtpHost  string
	smtpPort  int
	auth      *gomail.Dialer
	emailChan chan models.EmailChan
	stopChan  chan bool
}

func NewEmail(from, username, password, smtpHost string, smtpPort int, emailChan chan models.EmailChan, stopChan chan bool) *Email {
	auth := gomail.NewDialer(smtpHost, smtpPort, username, password)
	return &Email{
		from:      from,
		username:  username,
		password:  password,
		smtpHost:  smtpHost,
		smtpPort:  smtpPort,
		auth:      auth,
		emailChan: emailChan,
		stopChan:  stopChan,
	}
}

func (e *Email) EmailSender() {
	var email models.EmailChan
	for {
		select {
		case email = <-e.emailChan:
			err := e.SendChangeIPMessage(email.To, email.IP)
			if err != nil {
				log.Printf("packages/email.go: emailsender: sendchangeipmessage: %w", err)
			}
		case <-e.stopChan:
			fmt.Println("Email sender stopped")
			return
		}

	}
}

func (e *Email) SendChangeIPMessage(to, ip string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", e.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Warning: New IP Detected")
	m.SetBody("text/html", "We noticed a new IP address logging in.\nPlease change your password if it wasn't you.\nNew IP: "+ip)

	if err := e.auth.DialAndSend(m); err != nil {
		return fmt.Errorf("packages/email.go: sendemailchangeip: dialandsend: %w", err)
	}
	return nil
}
