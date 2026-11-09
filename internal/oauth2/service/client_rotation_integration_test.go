//go:build integration

package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/rushairer/gosso/internal/oauth2/domain"
	"github.com/rushairer/gosso/internal/oauth2/repository"
	"github.com/rushairer/gosso/internal/oauth2/service"
	"github.com/rushairer/gosso/internal/testutil"
)

type rotationFixture struct {
	env          *testutil.TestEnv
	repo         repository.OAuth2ClientRepository
	svc          service.OAuth2ClientService
	owner, actor string
	client       *domain.OAuth2Client
	original     string
}

func newRotationFixture(t *testing.T) rotationFixture {
	t.Helper()
	env := testutil.SetupTestEnvT(t)
	ctx := context.Background()
	var owner, actor string
	require.NoError(t, env.DB.QueryRowContext(ctx,
		`INSERT INTO accounts(display_name) VALUES('Rotation owner') RETURNING id`).Scan(&owner))
	require.NoError(t, env.DB.QueryRowContext(ctx,
		`INSERT INTO accounts(display_name) VALUES('Rotation administrator') RETURNING id`).Scan(&actor))
	repo := repository.NewOAuth2ClientRepository(env.DB)
	svc := service.NewOAuth2ClientService(env.DB, repo, nil, zap.NewNop())
	client, original, err := svc.RegisterClient(ctx, &service.RegisterClientRequest{
		AccountID: owner, Name: "Secret rotation regression",
		RedirectURIs: []string{"https://rotation.example.test/callback"},
		GrantTypes:   []string{domain.GrantTypeAuthorizationCode},
		Scopes:       []string{"openid"}, IsConfidential: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := env.DB.ExecContext(ctx, `DELETE FROM oauth2_clients WHERE client_id=$1`, client.ClientID)
		require.NoError(t, cleanupErr)
		_, cleanupErr = env.DB.ExecContext(ctx, `DELETE FROM accounts WHERE id IN ($1,$2)`, owner, actor)
		require.NoError(t, cleanupErr)
	})
	return rotationFixture{env: env, repo: repo, svc: svc, owner: owner, actor: actor, client: client, original: original}
}

func assertCredential(t *testing.T, f rotationFixture, accepted, rejected string) {
	t.Helper()
	current, err := f.repo.FindByClientID(context.Background(), f.client.ClientID)
	require.NoError(t, err)
	authenticator := &service.ClientAuthenticator{}
	require.NoError(t, authenticator.AuthenticateClient(current, accepted), "replacement must authenticate from a fresh database read")
	require.ErrorIs(t, authenticator.AuthenticateClient(current, rejected), service.ErrInvalidClientSecret, "retired credential must be rejected")
}

func TestClientSecretRotationPersistence(t *testing.T) {
	for _, mode := range []string{"owner", "administrator"} {
		t.Run(mode, func(t *testing.T) {
			f := newRotationFixture(t)
			ctx := context.Background()
			// Keep a pre-rotation object to prove later ordinary metadata writes
			// cannot accidentally restore its retired credential hash.
			stale, err := f.repo.FindByClientID(ctx, f.client.ClientID)
			require.NoError(t, err)
			var replacement string
			if mode == "owner" {
				replacement, err = f.svc.RotateClientSecret(ctx, f.owner, f.client.ClientID)
			} else {
				replacement, err = f.svc.RotateClientSecretAsAdmin(ctx, f.actor, f.client.ClientID)
			}
			require.NoError(t, err)
			assertCredential(t, f, replacement, f.original)
			stale.Name = "Metadata after credential rotation"
			require.NoError(t, f.svc.UpdateClient(ctx, stale))
			assertCredential(t, f, replacement, f.original)
			current, err := f.repo.FindByClientID(ctx, f.client.ClientID)
			require.NoError(t, err)
			require.Equal(t, stale.Name, current.Name)
			require.Equal(t, f.owner, current.AccountID, "administration must preserve ownership")
		})
	}
}

func TestClientSecretRotationOwnershipDenied(t *testing.T) {
	f := newRotationFixture(t)
	_, err := f.svc.RotateClientSecret(context.Background(), f.actor, f.client.ClientID)
	require.ErrorIs(t, err, service.ErrClientAccessDenied)
	current, err := f.repo.FindByClientID(context.Background(), f.client.ClientID)
	require.NoError(t, err)
	require.NoError(t, (&service.ClientAuthenticator{}).AuthenticateClient(current, f.original))
}

func TestClientSecretRotationRollback(t *testing.T) {
	f := newRotationFixture(t)
	ctx := context.Background()
	current, err := f.repo.FindByClientID(ctx, f.client.ClientID)
	require.NoError(t, err)
	expected := current.UpdatedAt
	const replacement = "synthetic-rollback-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(replacement), bcrypt.MinCost)
	require.NoError(t, err)
	current.ClientSecretHash = string(hash)
	tx, err := f.env.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	require.NoError(t, f.repo.UpdateSecret(ctx, tx, current, expected))
	require.NoError(t, tx.Rollback())
	assertCredential(t, f, f.original, replacement)
}

func TestClientSecretRotationConcurrentCAS(t *testing.T) {
	f := newRotationFixture(t)
	ctx := context.Background()
	tx1, err := f.env.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx1.Rollback() })
	tx2, err := f.env.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx2.Rollback() })
	first, err := f.repo.FindByClientIDTx(ctx, tx1, f.client.ClientID)
	require.NoError(t, err)
	second, err := f.repo.FindByClientIDTx(ctx, tx2, f.client.ClientID)
	require.NoError(t, err)
	expected1, expected2 := first.UpdatedAt, second.UpdatedAt
	const winner, loser = "synthetic-first-secret", "synthetic-stale-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(winner), bcrypt.MinCost)
	require.NoError(t, err)
	first.ClientSecretHash = string(hash)
	hash, err = bcrypt.GenerateFromPassword([]byte(loser), bcrypt.MinCost)
	require.NoError(t, err)
	second.ClientSecretHash = string(hash)
	require.NoError(t, f.repo.UpdateSecret(ctx, tx1, first, expected1))
	require.NoError(t, tx1.Commit())
	require.ErrorIs(t, f.repo.UpdateSecret(ctx, tx2, second, expected2), domain.ErrClientConcurrentModification)
	require.NoError(t, tx2.Rollback())
	assertCredential(t, f, winner, loser)
	assertCredential(t, f, winner, f.original)
}

func TestClientSecretRotationDeletedClient(t *testing.T) {
	f := newRotationFixture(t)
	ctx := context.Background()
	current, err := f.repo.FindByClientID(ctx, f.client.ClientID)
	require.NoError(t, err)
	tx, err := f.env.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	require.NoError(t, f.repo.SoftDelete(ctx, tx, current.ID, time.Now()))
	require.NoError(t, tx.Commit())
	tx, err = f.env.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	require.ErrorIs(t, f.repo.UpdateSecret(ctx, tx, current, current.UpdatedAt), domain.ErrClientNotFound)
	require.NoError(t, tx.Rollback())
}
