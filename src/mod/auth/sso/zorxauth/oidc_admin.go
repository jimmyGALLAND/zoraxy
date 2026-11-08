package zorxauth

import (
	"encoding/json"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/utils"
)

type oidcClientRequest struct {
	Name        string   `json:"name"`
	ProxyDomain string   `json:"proxy_domain"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientID    string   `json:"client_id"`
}

// HandleOIDCClients exposes client administration through the authenticated Zoraxy management API.
func (ar *AuthRouter) HandleOIDCClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		clients, err := ar.GetOIDCClients()
		if err != nil {
			utils.SendErrorResponse(w, "failed to list OIDC clients")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"clients": clients})
	case http.MethodPost:
		var request oidcClientRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			utils.SendErrorResponse(w, "invalid request body")
			return
		}
		request.Name = strings.TrimSpace(request.Name)
		request.ProxyDomain = strings.TrimSpace(request.ProxyDomain)
		if request.Name == "" || len(request.RedirectURIs) == 0 {
			utils.SendErrorResponse(w, "name and redirect_uris are required")
			return
		}
		client, secret, err := ar.RegisterOIDCClient(request.Name, request.ProxyDomain, request.RedirectURIs)
		if err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"client": client,
			"client_secret": secret,
			"warning": "The client secret is shown only once. Store it securely.",
		})
	case http.MethodDelete:
		var request oidcClientRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
			utils.SendErrorResponse(w, "invalid request body")
			return
		}
		if strings.TrimSpace(request.ClientID) == "" {
			utils.SendErrorResponse(w, "client_id is required")
			return
		}
		if err := ar.DeleteOIDCClient(request.ClientID); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		utils.SendOK(w)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
