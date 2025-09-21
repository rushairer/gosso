package service

import "gosso/internal/context"

type AuthService struct {
}

func (a *AuthService) ValidateToken(token string) (*context.AuthInfo, error) {
	return nil, nil
}
