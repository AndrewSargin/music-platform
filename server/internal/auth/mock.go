package auth

import (
	"context"
	"fmt"

	"github.com/AndrewSargin/music-platform/server/internal/user"
)

type mockUserRepository struct {
	createErr error
	created   *user.User
}

func (m *mockUserRepository) Create(
	ctx context.Context,
	input *user.User,
) error {
	fmt.Println("MOCK CREATE")
	m.created = input
	return m.createErr
}
