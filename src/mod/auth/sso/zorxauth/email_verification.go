package zorxauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	emailSMTPConfigKey       = "email_smtp"
	emailVerificationLifetime = time.Hour
	emailVerificationCooldown = time.Minute
)

type EmailSMTPConfig struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Security   string `json:"security"` // none, starttls, or tls
	Username   string `json:"username"`
	Password   string `json:"password"`
	FromEmail  string `json:"fromEmail"`
	FromName   string `json:"fromName"`
}

func (ar *AuthRouter) loadEmailSMTPConfig() (*EmailSMTPConfig, error) {
	config := &EmailSMTPConfig{}
	if ar.Database == nil || !ar.Database.KeyExists(DB_NAME, emailSMTPConfigKey) {
		return config, nil
	}
	if err := ar.Database.Read(DB_NAME, emailSMTPConfigKey, config); err != nil {
		return nil, err
	}
	return config, nil
}

func (ar *AuthRouter) saveEmailSMTPConfig(config *EmailSMTPConfig) error {
	if config == nil {
		return errors.New("SMTP configuration is missing")
	}
	return ar.Database.Write(DB_NAME, emailSMTPConfigKey, config)
}

func (config *EmailSMTPConfig) validate() error {
	config.Host = strings.TrimSpace(config.Host)
	config.Security = strings.ToLower(strings.TrimSpace(config.Security))
	config.FromEmail = strings.TrimSpace(config.FromEmail)
	config.FromName = strings.TrimSpace(config.FromName)
	config.Username = strings.TrimSpace(config.Username)

	if config.Host == "" {
		return errors.New("SMTP host is required")
	}
	// Accept either a hostname/IP address or an smtp:// / smtps:// URL.
	// Transport security remains controlled by the dedicated security setting.
	if strings.Contains(config.Host, "://") {
		serverURL, err := url.Parse(config.Host)
		if err != nil || (serverURL.Scheme != "smtp" && serverURL.Scheme != "smtps") ||
			serverURL.Hostname() == "" || serverURL.User != nil ||
			(serverURL.Path != "" && serverURL.Path != "/") || serverURL.RawQuery != "" || serverURL.Fragment != "" {
			return errors.New("SMTP URL must contain only an smtp:// or smtps:// server address")
		}
		if serverURL.Port() != "" {
			urlPort, _ := strconv.Atoi(serverURL.Port())
			if config.Port != 0 && config.Port != urlPort {
				return errors.New("SMTP URL port conflicts with the configured port")
			}
			config.Port = urlPort
		}
		config.Host = serverURL.Hostname()
	}
	if config.Port < 1 || config.Port > 65535 {
		return errors.New("SMTP port must be between 1 and 65535")
	}
	switch config.Security {
	case "none", "starttls", "tls":
	default:
		return errors.New("SMTP security must be none, starttls, or tls")
	}
	if config.Security == "none" && (config.Username != "" || config.Password != "") {
		return errors.New("SMTP authentication requires STARTTLS or SSL/TLS")
	}
	if config.Username != "" && config.Password == "" {
		return errors.New("SMTP password is required when a username is configured")
	}
	sender, err := mail.ParseAddress(config.FromEmail)
	if err != nil || sender.Address != config.FromEmail {
		return errors.New("a valid sender email address without a display name is required")
	}
	return nil
}

func (ar *AuthRouter) sendEmail(to, subject, body string) error {
	config, err := ar.loadEmailSMTPConfig()
	if err != nil {
		return fmt.Errorf("could not load SMTP configuration: %w", err)
	}
	if err := config.validate(); err != nil {
		return fmt.Errorf("SMTP is not configured: %w", err)
	}
	recipient, err := mail.ParseAddress(to)
	if err != nil {
		return errors.New("invalid recipient email address")
	}

	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if config.Security == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName: config.Host,
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return fmt.Errorf("SMTP connection failed: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = conn.Close()
		return fmt.Errorf("could not set SMTP connection deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, config.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMTP client initialization failed: %w", err)
	}
	defer client.Close()

	if config.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("SMTP STARTTLS failed: %w", err)
		}
	}
	if config.Username != "" {
		auth := smtp.PlainAuth("", config.Username, config.Password, config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	from := config.FromEmail
	if _, err := mail.ParseAddress(from); err != nil {
		return errors.New("invalid SMTP sender address")
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("SMTP sender rejected: %w", err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("SMTP recipient rejected: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command failed: %w", err)
	}

	fromHeader := from
	if config.FromName != "" {
		fromHeader = (&mail.Address{Name: config.FromName, Address: from}).String()
	}
	message := "From: " + fromHeader + "\r\n" +
		"To: " + recipient.String() + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" + body
	if _, err := writer.Write([]byte(message)); err != nil {
		writer.Close()
		return fmt.Errorf("SMTP message write failed: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("SMTP message delivery failed: %w", err)
	}
	return client.Quit()
}

func (ar *AuthRouter) createEmailVerification(username string) error {
	var rawToken [32]byte
	if _, err := rand.Read(rawToken[:]); err != nil {
		return fmt.Errorf("could not generate verification token: %w", err)
	}
	token := hex.EncodeToString(rawToken[:])
	tokenHash := sha256.Sum256([]byte(token))
	now := time.Now()
	baseURL := strings.TrimRight(ar.OIDCIssuer(), "/")
	parsedURL, err := url.Parse(baseURL)
	if err != nil || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") || parsedURL.Host == "" {
		return errors.New("OIDC issuer must be configured with an absolute public URL before email verification can be sent")
	}

	user, err := ar.updateUser(username, func(user *User) error {
		if user.Email == "" {
			return errors.New("account has no email address")
		}
		if user.EmailVerified {
			return errors.New("email address is already verified")
		}
		if !user.EmailVerificationSentAt.IsZero() && now.Sub(user.EmailVerificationSentAt) < emailVerificationCooldown {
			return errors.New("please wait before requesting another verification email")
		}
		user.EmailVerificationTokenHash = hex.EncodeToString(tokenHash[:])
		user.EmailVerificationExpiresAt = now.Add(emailVerificationLifetime)
		user.EmailVerificationSentAt = now
		return nil
	})
	if err != nil {
		return err
	}

	verifyURL := baseURL + "/email/verify?token=" + url.QueryEscape(token)
	body := "Hello " + user.Username + ",\n\n" +
		"Please confirm your email address by opening the following link:\n" + verifyURL + "\n\n" +
		"This link expires in one hour and can only be used once.\n\n" +
		"If you did not request this message, you can ignore it."
	if err := ar.sendEmail(user.Email, "Verify your email address", body); err != nil {
		// Do not keep a valid token when delivery failed.
		_, _ = ar.updateUser(username, func(current *User) error {
			if current.EmailVerificationTokenHash == hex.EncodeToString(tokenHash[:]) {
				current.EmailVerificationTokenHash = ""
				current.EmailVerificationExpiresAt = time.Time{}
				current.EmailVerificationSentAt = time.Time{}
			}
			return nil
		})
		return err
	}
	return nil
}

func (ar *AuthRouter) verifyEmailToken(token string) error {
	if len(token) != 64 {
		return errors.New("verification link is invalid or has expired")
	}
	sum := sha256.Sum256([]byte(token))
	expectedHash := hex.EncodeToString(sum[:])

	ar.userMutationMutex.Lock()
	defer ar.userMutationMutex.Unlock()

	users, err := ar.listUsers()
	if err != nil {
		return errors.New("could not load user records")
	}
	for _, user := range users {
		if user.EmailVerificationTokenHash != expectedHash {
			continue
		}
		if user.EmailVerificationExpiresAt.IsZero() || time.Now().After(user.EmailVerificationExpiresAt) {
			user.EmailVerificationTokenHash = ""
			user.EmailVerificationExpiresAt = time.Time{}
			if err := ar.saveUser(user, user.Username); err != nil {
				return errors.New("could not clear expired email verification token")
			}
			return errors.New("verification link is invalid or has expired")
		}
		user.EmailVerified = true
		user.EmailVerificationTokenHash = ""
		user.EmailVerificationExpiresAt = time.Time{}
		if err := ar.saveUser(user, user.Username); err != nil {
			return errors.New("could not save email verification")
		}
		return nil
	}
	return errors.New("verification link is invalid or has expired")
}
