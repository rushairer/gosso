package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	oauth2Repo "github.com/rushairer/gosso/internal/oauth2/repository"
	sessionService "github.com/rushairer/gosso/internal/session/service"
	tokenService "github.com/rushairer/gosso/internal/token/service"
	"github.com/rushairer/gosso/internal/utility"
)

// LogoutService handles OIDC RP-Initiated Logout, Front-Channel Logout, and
// Back-Channel Logout operations.
type LogoutService struct {
	tokenSvc   *tokenService.TokenService
	sessionSvc *sessionService.SessionService
	jwksSvc    *JWKSService // for key rotation fallback in id_token_hint validation
	clientRepo oauth2Repo.OAuth2ClientRepository
	httpClient *http.Client
	issuer     string
	logger     *zap.Logger
	parser     *jwt.Parser
}

// NewLogoutService creates a new LogoutService.
func NewLogoutService(
	tokenSvc *tokenService.TokenService,
	sessionSvc *sessionService.SessionService,
	jwksSvc *JWKSService,
	issuer string,
	clientRepo oauth2Repo.OAuth2ClientRepository,
	httpClient *http.Client,
	logger *zap.Logger,
) *LogoutService {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &LogoutService{
		tokenSvc:   tokenSvc,
		sessionSvc: sessionSvc,
		jwksSvc:    jwksSvc,
		clientRepo: clientRepo,
		httpClient: httpClient,
		issuer:     issuer,
		logger:     logger,
		parser:     jwt.NewParser(jwt.WithoutClaimsValidation()),
	}
}

// ValidateIDTokenHint validates an ID token hint per OIDC RP-Initiated Logout spec.
// The OP SHOULD accept expired ID tokens, so expiry is not checked.
// Only signature, issuer, and audience are validated.
// If clientID is non-empty, the token's audience must contain it (OIDC RP-Initiated Logout §2).
func (s *LogoutService) ValidateIDTokenHint(tokenString string, clientID string) (*IDTokenClaims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty id_token_hint")
	}

	parser := s.parser
	claims := &IDTokenClaims{}

	// keyFunc resolves the RSA public key for signature verification.
	// Tries the current key first; on failure, falls back to JWKS-published keys
	// (including the previous key during rotation overlap).
	keyFunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Try current key first
		currentKey := s.tokenSvc.KeyService().PublicKey()
		return currentKey, nil
	}

	token, err := parser.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil && s.jwksSvc != nil {
		// Current key failed — try JWKS fallback (handles key rotation overlap).
		// Extract kid from token header and look up in JWKS.
		var kid string
		if hdr, _, parseErr := parser.ParseUnverified(tokenString, jwt.MapClaims{}); parseErr == nil {
			if k, ok := hdr.Header["kid"].(string); ok {
				kid = k
			}
		}
		if kid != "" && kid != s.tokenSvc.KeyService().KeyID() {
			// kid present and differs from current key — look up by ID.
			if pubKey, jwksErr := s.jwksSvc.GetPublicKeyByKID(kid); jwksErr == nil {
				claims = &IDTokenClaims{}
				token, err = parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
					return pubKey, nil
				})
			}
		} else {
			// kid is absent or matches current key — try all available keys.
			// This handles the case where a token was signed with the previous key
			// but has no "kid" header (valid per JWT spec), e.g. during key rotation.
			for _, pubKey := range s.jwksSvc.GetAllPublicKeys() {
				claims = &IDTokenClaims{}
				token, err = parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
					return pubKey, nil
				})
				if err == nil && token.Valid {
					break
				}
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parse id_token_hint: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid id_token_hint signature")
	}

	// Manual validation: issuer must match, audience must be non-empty
	if claims.Issuer != s.issuer {
		return nil, fmt.Errorf("id_token_hint issuer mismatch")
	}
	if len(claims.Audience) == 0 {
		return nil, fmt.Errorf("id_token_hint has no audience")
	}

	// OIDC RP-Initiated Logout §2: validate that the token was issued to the requesting client.
	if clientID != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == clientID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: token audience %v does not contain %q", ErrAudienceMismatch, claims.Audience, clientID)
		}
	}

	return claims, nil
}

var (
	// ErrSessionServiceNotConfigured is returned when the session service is not available.
	ErrSessionServiceNotConfigured = errors.New("session service not configured")

	// ErrAudienceMismatch is returned when the id_token_hint audience does not contain the requested client_id.
	ErrAudienceMismatch = errors.New("id_token_hint audience does not match client_id")
)

// LogoutByAccountID revokes all sessions and refresh tokens for the given account.
// Token revocation is handled internally by SessionService.RevokeAllForAccount via its TokenRevoker.
func (s *LogoutService) LogoutByAccountID(ctx context.Context, accountID string) error {
	if s.sessionSvc == nil {
		return ErrSessionServiceNotConfigured
	}

	if err := s.sessionSvc.RevokeAllForAccount(ctx, accountID); err != nil {
		return fmt.Errorf("revoke all sessions for account: %w", err)
	}

	// Revoke all outstanding access tokens for this account.
	// Uses a "revoke after" timestamp — tokens issued before this time will be
	// rejected by ValidateAccessTokenWithContext.
	if err := s.tokenSvc.RevokeAccountTokens(ctx, accountID); err != nil {
		s.logger.Warn("Failed to revoke access tokens for account during logout",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
		// Non-fatal: sessions and refresh tokens are already revoked above.
		// The JWT middleware's session check provides a secondary defense.
	}

	s.logger.Info("Account logout successful", zap.String("account_id", utility.MaskOpaqueID(accountID)))

	// Trigger back-channel logout notifications to all registered clients.
	s.triggerBackChannelLogout(ctx, accountID, "")

	return nil
}

// LogoutBySessionID deletes a single session and revokes its refresh tokens.
func (s *LogoutService) LogoutBySessionID(ctx context.Context, accountID, sessionID string) error {
	if s.sessionSvc == nil {
		return ErrSessionServiceNotConfigured
	}

	// Revoke session FIRST so that even if token revocation fails,
	// the session is already invalidated.
	if err := s.sessionSvc.RevokeSession(ctx, accountID, sessionID); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	if err := s.tokenSvc.RevokeAllForSession(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to revoke tokens for session during logout",
			zap.String("session_id", utility.MaskOpaqueID(sessionID)), zap.Error(err))
	}

	s.logger.Info("Session logout successful",
		zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.String("session_id", utility.MaskOpaqueID(sessionID)))
	return nil
}

// ──────────────────────────────────────────────
// Front-Channel Logout (OIDC Front-Channel Logout 1.0)
// ──────────────────────────────────────────────

// FrontChannelLogoutEntry represents a client's front-channel logout endpoint.
type FrontChannelLogoutEntry struct {
	URI             string
	SessionRequired bool
	ClientID        string
}

// GetFrontChannelLogoutURIs returns front-channel logout entries for all clients
// that have a non-empty frontchannel_logout_uri and a consent record for the given account.
func (s *LogoutService) GetFrontChannelLogoutURIs(ctx context.Context, accountID string) ([]FrontChannelLogoutEntry, error) {
	if s.clientRepo == nil {
		return nil, nil
	}

	clients, err := s.clientRepo.FindFrontchannelLogoutClientsByAccountID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("find frontchannel logout clients: %w", err)
	}

	entries := make([]FrontChannelLogoutEntry, 0, len(clients))
	for _, c := range clients {
		entries = append(entries, FrontChannelLogoutEntry{
			URI:             c.FrontchannelLogoutURI,
			SessionRequired: c.FrontchannelLogoutSessionRequired,
			ClientID:        c.ClientID,
		})
	}
	return entries, nil
}

// ──────────────────────────────────────────────
// Back-Channel Logout (OIDC Back-Channel Logout 1.0)
// ──────────────────────────────────────────────

// LogoutTokenClaims represents the claims in a back-channel logout token.
// Per OIDC Back-Channel Logout §2.4, the logout token contains the standard
// registered claims plus an "events" claim and optional "sid" claim.
type LogoutTokenClaims struct {
	jwt.RegisteredClaims
	Events map[string]map[string]any `json:"events"`
	SID    string                    `json:"sid,omitempty"`
}

// sendBackChannelLogoutAsync asynchronously sends a logout_token to the given
// backchannel_logout_uri for a single client. Fire-and-forget: errors are logged
// but do not block the caller.
func (s *LogoutService) sendBackChannelLogoutAsync(clientID, accountID, sessionID, backchannelURI string, sessionRequired bool) {
	go func() {
		// 5-second timeout for the HTTP POST
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		logoutToken, err := s.generateLogoutToken(clientID, accountID, sessionID, sessionRequired)
		if err != nil {
			s.logger.Error("Failed to generate back-channel logout token",
				zap.String("client_id", clientID), zap.Error(err))
			return
		}

		form := url.Values{}
		form.Set("logout_token", logoutToken)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, backchannelURI, strings.NewReader(form.Encode()))
		if err != nil {
			s.logger.Error("Failed to create back-channel logout request",
				zap.String("client_id", clientID), zap.String("uri", backchannelURI), zap.Error(err))
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			s.logger.Warn("Back-channel logout POST failed",
				zap.String("client_id", clientID), zap.String("uri", backchannelURI), zap.Error(err))
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 400 {
			s.logger.Warn("Back-channel logout POST returned error status",
				zap.String("client_id", clientID), zap.String("uri", backchannelURI),
				zap.Int("status", resp.StatusCode))
		} else {
			s.logger.Debug("Back-channel logout POST succeeded",
				zap.String("client_id", clientID), zap.String("uri", backchannelURI))
		}
	}()
}

// generateLogoutToken creates a signed JWT logout token per OIDC Back-Channel Logout §2.4.
func (s *LogoutService) generateLogoutToken(clientID, accountID, sessionID string, sessionRequired bool) (string, error) {
	now := time.Now()
	claims := &LogoutTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   accountID,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        uuid.New().String(),
		},
		Events: map[string]map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": {},
		},
	}
	if sessionRequired && sessionID != "" {
		claims.SID = sessionID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.tokenSvc.KeyService().KeyID()

	privateKey := s.tokenSvc.KeyService().PrivateKey()
	if privateKey == nil {
		return "", fmt.Errorf("no private key available for signing logout token")
	}

	return token.SignedString(privateKey)
}

// triggerBackChannelLogout sends back-channel logout notifications to all clients
// that have a non-empty backchannel_logout_uri and a consent record for the account.
func (s *LogoutService) triggerBackChannelLogout(ctx context.Context, accountID, sessionID string) {
	if s.clientRepo == nil {
		return
	}

	clients, err := s.clientRepo.FindBackchannelLogoutClientsByAccountID(ctx, accountID)
	if err != nil {
		s.logger.Warn("Failed to find backchannel logout clients",
			zap.String("account_id", utility.MaskOpaqueID(accountID)), zap.Error(err))
		return
	}

	for _, c := range clients {
		s.sendBackChannelLogoutAsync(c.ClientID, accountID, sessionID, c.BackchannelLogoutURI, c.BackchannelLogoutSessionRequired)
	}
}
