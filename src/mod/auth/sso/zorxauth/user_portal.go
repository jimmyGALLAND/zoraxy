package zorxauth

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"imuslab.com/zoraxy/mod/utils"
)

//go:embed user.html
var userPortalHTML []byte

// handleUserPortal serves the user self-service portal page.
// The user must already hold a valid SSO gateway session cookie.
func (gs *GatewayServer) handleUserPortal(w http.ResponseWriter, r *http.Request) {
	if gs.ServeGatewayDisabled(w, r) {
		return
	}

	authenticated, _ := gs.router.RequestIsAuthenticatedInSSO(w, r)
	if !authenticated {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(userPortalHTML)
}

// handleUserPortalAPI dispatches /user/api/* requests.
func (gs *GatewayServer) handleUserPortalAPI(w http.ResponseWriter, r *http.Request) {
	if gs.ServeGatewayDisabled(w, r) {
		return
	}

	authenticated, username := gs.router.RequestIsAuthenticatedInSSO(w, r)
	if !authenticated {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Unauthorized",
		})
		return
	}

	sub := strings.TrimPrefix(r.URL.Path, "/user/api/")

	switch sub {
	case "info":
		gs.handleUserInfo(w, r, username)
	case "email/resend-verification":
		gs.handleResendEmailVerification(w, r, username)
	case "change-password":
		gs.handleChangePassword(w, r, username)
	case "2fa/setup":
		gs.handleSetupTOTP(w, r, username)
	case "2fa/enable":
		gs.handleEnableTOTP(w, r, username)
	case "2fa/disable":
		gs.handleDisableTOTP(w, r, username)
	case "passkey/register/begin":
		gs.handlePasskeyRegisterBegin(w, r, username)
	case "passkey/register/complete":
		gs.handlePasskeyRegisterComplete(w, r, username)
	case "passkey/list":
		gs.handlePasskeyList(w, r, username)
	case "passkey/remove":
		gs.handlePasskeyRemove(w, r, username)
	default:
		http.NotFound(w, r)
	}
}

// handleUserInfo returns the current user's non-sensitive profile.
func (gs *GatewayServer) handleUserInfo(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}

	u, err := gs.router.getUserByUsername(username)
	if err != nil {
		utils.SendErrorResponse(w, "user not found")
		return
	}

	js, _ := json.Marshal(map[string]interface{}{
		"username":     u.Username,
		"email":        u.Email,
		"emailVerified": u.EmailVerified,
		"enable2fa":    u.Enable2FA,
		"passkeyCount": len(u.PasskeyCredentials),
	})
	utils.SendJSONResponse(w, string(js))
}

// handleChangePassword verifies the current password and stores the new hash.
func (gs *GatewayServer) handleChangePassword(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}

	currentPassword, err := utils.PostPara(r, "current_password")
	if err != nil {
		utils.SendErrorResponse(w, "current_password is required")
		return
	}

	newPassword, err := utils.PostPara(r, "new_password")
	if err != nil {
		utils.SendErrorResponse(w, "new_password is required")
		return
	}

	if len(newPassword) < 8 {
		utils.SendErrorResponse(w, "new password must be at least 8 characters")
		return
	}

	u, err := gs.router.updateUser(username, func(user *User) error {
		if user.PasswordHash == "" || user.PasswordHash != hashPassword(currentPassword) {
			return errors.New("current password is incorrect")
		}
		user.PasswordHash = hashPassword(newPassword)
		return nil
	})
	if err != nil {
		utils.SendErrorResponse(w, "failed to save new password: "+err.Error())
		return
	}

	// A password change revokes every existing session and pending authentication flow.
	gs.router.invalidateUserSessions(u.Username)
	utils.SendOK(w)
}

// handleSetupTOTP generates a new TOTP secret and returns the QR code.
// The secret is stored as pending until the user confirms it with handleEnableTOTP.
func (gs *GatewayServer) handleSetupTOTP(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}

	u, err := gs.router.getUserByUsername(username)
	if err != nil {
		utils.SendErrorResponse(w, "user not found")
		return
	}

	if u.Enable2FA {
		utils.SendErrorResponse(w, "2FA is already enabled; disable it first to re-enroll")
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Zoraxy Auth",
		AccountName: username,
	})
	if err != nil {
		utils.SendErrorResponse(w, "failed to generate TOTP secret")
		return
	}

	gs.router.pendingTOTPSetup.Store(username, &PendingTOTPSetup{
		Secret: key.Secret(),
		Expiry: time.Now().Add(10 * time.Minute),
	})
	time.AfterFunc(10*time.Minute, func() {
		gs.router.pendingTOTPSetup.Delete(username)
	})

	// Render QR code PNG and base64-encode it for inline display
	var qrDataURL string
	if img, imgErr := key.Image(200, 200); imgErr == nil {
		var buf bytes.Buffer
		if encErr := png.Encode(&buf, img); encErr == nil {
			qrDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
		}
	}

	js, _ := json.Marshal(map[string]interface{}{
		"secret":           key.Secret(),
		"provisioning_uri": key.URL(),
		"qr_image":         qrDataURL,
	})
	utils.SendJSONResponse(w, string(js))
}

// handleEnableTOTP validates the TOTP code against the pending secret and activates 2FA.
func (gs *GatewayServer) handleEnableTOTP(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}

	code, err := utils.PostPara(r, "totp_code")
	if err != nil {
		utils.SendErrorResponse(w, "totp_code is required")
		return
	}

	pendingObj, exists := gs.router.pendingTOTPSetup.Load(username)
	if !exists {
		utils.SendErrorResponse(w, "no pending 2FA setup found; please start setup again")
		return
	}

	pending, ok := pendingObj.(*PendingTOTPSetup)
	if !ok || pending == nil || time.Now().After(pending.Expiry) {
		gs.router.pendingTOTPSetup.Delete(username)
		utils.SendErrorResponse(w, "2FA setup session expired; please start setup again")
		return
	}

	if !totp.Validate(code, pending.Secret) {
		utils.SendErrorResponse(w, "invalid TOTP code; please try again")
		return
	}

	_, err = gs.router.updateUser(username, func(user *User) error {
		if user.Enable2FA {
			return errors.New("2FA is already enabled")
		}
		user.TOTPSecret = pending.Secret
		user.Enable2FA = true
		return nil
	})
	if err != nil {
		utils.SendErrorResponse(w, "failed to enable 2FA: "+err.Error())
		return
	}

	gs.router.pendingTOTPSetup.CompareAndDelete(username, pending)
	utils.SendOK(w)
}

// handleDisableTOTP verifies the current TOTP code and removes 2FA from the account.
func (gs *GatewayServer) handleDisableTOTP(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}

	code, err := utils.PostPara(r, "totp_code")
	if err != nil {
		utils.SendErrorResponse(w, "totp_code is required")
		return
	}

	_, err = gs.router.updateUser(username, func(user *User) error {
		if !user.Enable2FA {
			return errors.New("2FA is not currently enabled")
		}
		if !totp.Validate(code, user.TOTPSecret) {
			return errors.New("invalid TOTP code")
		}
		user.Enable2FA = false
		user.TOTPSecret = ""
		return nil
	})
	if err != nil {
		utils.SendErrorResponse(w, "failed to disable 2FA: "+err.Error())
		return
	}

	utils.SendOK(w)
}


// handleResendEmailVerification sends a fresh, rate-limited verification link
// to the email address currently associated with the authenticated account.
func (gs *GatewayServer) handleResendEmailVerification(w http.ResponseWriter, r *http.Request, username string) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}
	if err := gs.router.createEmailVerification(username); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// handleEmailVerification requires an explicit POST confirmation so automated
// email link scanners cannot consume a single-use verification token.
func (gs *GatewayServer) handleEmailVerification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

	switch r.Method {
	case http.MethodGet:
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" {
			http.Error(w, "Verification token is missing", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Confirm email address</title></head><body><main><h1>Confirm your email address</h1><p>Select the button below to verify your email address.</p><form method=\"post\" action=\"/email/verify\"><input type=\"hidden\" name=\"token\" value=\"%s\"><button type=\"submit\">Verify email address</button></form></main></body></html>", html.EscapeString(token))
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid verification request", http.StatusBadRequest)
			return
		}
		token := strings.TrimSpace(r.PostForm.Get("token"))
		if err := gs.router.verifyEmailToken(token); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Email verification failed</title></head><body><h1>Email verification failed</h1><p>%s</p></body></html>", html.EscapeString(err.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Email address verified</title></head><body><h1>Your email address has been verified</h1><p>You can close this page and return to the application.</p></body></html>")
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
