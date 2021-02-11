package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	clienttesting "k8s.io/client-go/testing"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthfake "github.com/openshift/client-go/oauth/clientset/versioned/fake"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userfake "github.com/openshift/client-go/user/clientset/versioned/fake"
)

func TestAuthenticateTokenInvalidUID(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset(
		&oauthv1.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "token", CreationTimestamp: metav1.Time{Time: time.Now()}},
			ExpiresIn:  600, // 10 minutes
			UserName:   "foo",
			UserUID:    string("bar1"),
		},
	)
	fakeUserClient := userfake.NewSimpleClientset(&userv1.User{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: "bar2"}})

	tokenAuthenticator := NewTokenAuthenticator(fakeOAuthClient.OauthV1().OAuthAccessTokens(), fakeUserClient.UserV1().Users(), NoopGroupMapper{}, nil, NewUIDValidator())

	userInfo, found, err := tokenAuthenticator.AuthenticateToken(context.TODO(), "token")
	if found {
		t.Error("Found token, but it should be missing!")
	}
	if err.Error() != "user.UID (bar2) does not match token.userUID (bar1)" {
		t.Errorf("Unexpected error: %v", err)
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}

func TestAuthenticateTokenNotFoundSuppressed(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset()
	fakeUserClient := userfake.NewSimpleClientset()
	tokenAuthenticator := NewTokenAuthenticator(fakeOAuthClient.OauthV1().OAuthAccessTokens(), fakeUserClient.UserV1().Users(), NoopGroupMapper{}, nil)

	userInfo, found, err := tokenAuthenticator.AuthenticateToken(context.TODO(), "token")
	if found {
		t.Error("Found token, but it should be missing!")
	}
	if err != errLookup {
		t.Error("Expected not found error to be suppressed with lookup error")
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}

func TestAuthenticateTokenOtherGetErrorSuppressed(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset()
	fakeOAuthClient.PrependReactor("get", "oauthaccesstokens", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, errors.New("get error")
	})
	fakeUserClient := userfake.NewSimpleClientset()
	tokenAuthenticator := NewTokenAuthenticator(fakeOAuthClient.OauthV1().OAuthAccessTokens(), fakeUserClient.UserV1().Users(), NoopGroupMapper{}, nil)

	userInfo, found, err := tokenAuthenticator.AuthenticateToken(context.TODO(), "token")
	if found {
		t.Error("Found token, but it should be missing!")
	}
	if err != errLookup {
		t.Error("Expected custom get error to be suppressed with lookup error")
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}







func checkToken(t *testing.T, name string, authf authenticator.Token, tokens oauthclient.OAuthAccessTokenInterface, current clock.Clock, present bool) {
	t.Helper()
	userInfo, found, err := authf.AuthenticateToken(context.TODO(), name)
	if present {
		if !found {
			t.Errorf("Did not find token %s!", name)
		}
		if err != nil {
			t.Errorf("Unexpected error checking for token %s: %v", name, err)
		}
		if userInfo == nil {
			t.Errorf("Did not get a user for token %s!", name)
		}
	} else {
		if found {
			token, tokenErr := tokens.Get(context.TODO(), name, metav1.GetOptions{})
			if tokenErr != nil {
				t.Fatal(tokenErr)
			}
			t.Errorf("Found token (created=%s, timeout=%di, now=%s), but it should be gone!",
				token.CreationTimestamp, token.InactivityTimeoutSeconds, current.Now())
		}
		if err != errTimedout {
			t.Errorf("Unexpected error checking absence of token %s: %v", name, err)
		}
		if userInfo != nil {
			t.Errorf("Unexpected user checking absence of token %s: %v", name, userInfo)
		}
	}
}

}
