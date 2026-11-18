package azblob

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
)

type copySourceToken struct {
	azcore.AccessToken
	generation uint64
}

// A copy's blocks share a token cache, not a frozen authorization header.
// This also avoids invoking Azure CLI once per block.
type copySourceAuth struct {
	credential azcore.TokenCredential
	mu         sync.Mutex
	token      copySourceToken
	refreshAt  time.Time
}

func (a *copySourceAuth) getToken(ctx context.Context, rejectedGeneration uint64) (copySourceToken, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return copySourceToken{}, err
	}
	now := time.Now()
	// Coalesce concurrent rejections, even if the provider returned the same
	// token: only the first failure of a generation forces another acquisition.
	rejected := rejectedGeneration != 0 && rejectedGeneration == a.token.generation
	if a.token.Token != "" && now.Before(a.refreshAt) && !rejected {
		return a.token, nil
	}
	token, err := a.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://storage.azure.com/.default"},
	})
	if err != nil {
		return copySourceToken{}, fmt.Errorf("refresh copy source authorization: %w", err)
	}
	now = time.Now()
	if token.Token == "" || !now.Before(token.ExpiresOn) {
		return copySourceToken{}, errors.New("copy source credential returned an empty or expired token")
	}
	a.token = copySourceToken{AccessToken: token, generation: a.token.generation + 1}
	a.refreshAt = token.ExpiresOn.Add(-5 * time.Minute)
	if !token.RefreshOn.IsZero() && token.RefreshOn.Before(a.refreshAt) {
		a.refreshAt = token.RefreshOn
	}
	// Providers may return the same still-valid token in the refresh window.
	// Recheck halfway through its remaining lifetime instead of on every block.
	if !now.Before(a.refreshAt) {
		a.refreshAt = now.Add(token.ExpiresOn.Sub(now) / 2)
	}
	return a.token, nil
}

func stageBlockFromURL(ctx context.Context, client *blockblob.Client, blockID, sourceURL string, options *blockblob.StageBlockFromURLOptions, auth *copySourceAuth) error {
	if auth == nil {
		_, err := client.StageBlockFromURL(ctx, blockID, sourceURL, options)
		return err
	}
	if !strings.HasPrefix(client.URL(), "https://") {
		return errors.New("copy source authorization requires an HTTPS destination")
	}
	token, err := auth.getToken(ctx, 0)
	if err != nil {
		return err
	}
	header := "Bearer " + token.Token
	options.CopySourceAuthorization = &header
	_, err = client.StageBlockFromURL(ctx, blockID, sourceURL, options)
	if !isCopySourceAuthFailure(err) {
		return err
	}
	fresh, refreshErr := auth.getToken(ctx, token.generation)
	if refreshErr != nil {
		return errors.Join(err, refreshErr)
	}
	// A credential isn't guaranteed to issue a different token on demand.
	// Don't replay an already rejected token or broadly retry permanent 401s.
	if fresh.Token == token.Token {
		return err
	}
	// Recreate the SDK request so destination SharedKey signing includes the
	// renewed source header. A per-retry policy would run after that signer.
	header = "Bearer " + fresh.Token
	_, err = client.StageBlockFromURL(ctx, blockID, sourceURL, options)
	return err
}

func isCopySourceAuthFailure(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) || respErr.StatusCode != http.StatusUnauthorized ||
		respErr.ErrorCode != "CannotVerifyCopySource" || respErr.RawResponse == nil {
		return false
	}
	payload, err := runtime.Payload(respErr.RawResponse)
	if err != nil {
		return false // Leave the original failure for the SDK to surface.
	}
	var details struct {
		Code                 string
		CopySourceStatusCode string
		CopySourceErrorCode  string
	}
	if err := xml.Unmarshal(payload, &details); err != nil {
		return false
	}
	return details.Code == "CannotVerifyCopySource" &&
		details.CopySourceStatusCode == "401" &&
		details.CopySourceErrorCode == "InvalidAuthenticationInfo"
}
