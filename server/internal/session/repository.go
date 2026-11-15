package session

import "context"

type SessionRepository interface {
	Create(ctx context.Context, session *SessionData) error
}
