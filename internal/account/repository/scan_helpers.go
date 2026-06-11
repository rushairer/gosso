package repository

import (
	"database/sql"
	"fmt"

	dbPkg "github.com/rushairer/gosso/internal/db"

	"github.com/rushairer/gosso/internal/account/domain"
)

// scanAccount scans a single Account from a scannable row.
func scanAccount(s dbPkg.Scannable) (*domain.Account, error) {
	account := &domain.Account{}
	var metadataJSON []byte

	err := s.Scan(
		&account.ID,
		&account.Username,
		&account.DisplayName,
		&account.AvatarURL,
		&account.Status,
		&account.Locale,
		&account.Timezone,
		&metadataJSON,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	account.Metadata = make(map[string]any)
	if err := dbPkg.UnmarshalJSONField(metadataJSON, &account.Metadata, "metadata"); err != nil {
		return nil, err
	}

	return account, nil
}

// scanAccounts scans multiple Account rows from an *sql.Rows iterator.
func scanAccounts(rows *sql.Rows) ([]*domain.Account, error) {
	var accounts []*domain.Account
	for rows.Next() {
		account, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		accounts = append(accounts, account)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate accounts: %w", err)
	}

	return accounts, nil
}

// scanRole scans a single Role from a scannable row.
func scanRole(s dbPkg.Scannable) (*domain.Role, error) {
	role := &domain.Role{}
	var permissionsJSON, metadataJSON []byte

	err := s.Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&permissionsJSON,
		&metadataJSON,
		&role.CreatedAt,
		&role.UpdatedAt,
		&role.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	role.Permissions = make([]string, 0)
	if err := dbPkg.UnmarshalJSONField(permissionsJSON, &role.Permissions, "permissions"); err != nil {
		return nil, err
	}

	role.Metadata = make(map[string]any)
	if err := dbPkg.UnmarshalJSONField(metadataJSON, &role.Metadata, "metadata"); err != nil {
		return nil, err
	}

	return role, nil
}

// scanRoles scans multiple Role rows from an *sql.Rows iterator.
func scanRoles(rows *sql.Rows) ([]*domain.Role, error) {
	var roles []*domain.Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate roles: %w", err)
	}

	return roles, nil
}

// scanCredential scans a single Credential from a scannable row.
func scanCredential(s dbPkg.Scannable) (*domain.Credential, error) {
	cred := &domain.Credential{}
	var metadataJSON []byte

	err := s.Scan(
		&cred.ID,
		&cred.AccountID,
		&cred.Type,
		&cred.Identifier,
		&cred.Value,
		&cred.Verified,
		&cred.PrimaryCredential,
		&metadataJSON,
		&cred.CreatedAt,
		&cred.VerifiedAt,
		&cred.LastUsedAt,
		&cred.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	cred.Metadata = make(map[string]any)
	if err := dbPkg.UnmarshalJSONField(metadataJSON, &cred.Metadata, "metadata"); err != nil {
		return nil, err
	}

	return cred, nil
}

// scanCredentials scans multiple Credential rows from an *sql.Rows iterator.
func scanCredentials(rows *sql.Rows) ([]*domain.Credential, error) {
	var credentials []*domain.Credential
	for rows.Next() {
		cred, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		credentials = append(credentials, cred)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}

	return credentials, nil
}

// scanFederatedIdentity scans a single FederatedIdentity from a scannable row.
func scanFederatedIdentity(s dbPkg.Scannable) (*domain.FederatedIdentity, error) {
	identity := &domain.FederatedIdentity{}
	var profileJSON []byte

	err := s.Scan(
		&identity.ID,
		&identity.AccountID,
		&identity.Provider,
		&identity.ProviderUserID,
		&profileJSON,
		&identity.CreatedAt,
		&identity.UpdatedAt,
		&identity.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	identity.Profile = make(map[string]any)
	if err := dbPkg.UnmarshalJSONField(profileJSON, &identity.Profile, "profile"); err != nil {
		return nil, err
	}

	return identity, nil
}

// scanFederatedIdentities scans multiple FederatedIdentity rows from an *sql.Rows iterator.
func scanFederatedIdentities(rows *sql.Rows) ([]*domain.FederatedIdentity, error) {
	var identities []*domain.FederatedIdentity
	for rows.Next() {
		identity, err := scanFederatedIdentity(rows)
		if err != nil {
			return nil, fmt.Errorf("scan federated identity: %w", err)
		}
		identities = append(identities, identity)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate federated identities: %w", err)
	}

	return identities, nil
}
