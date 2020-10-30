package tokenvalidation

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	corefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthfake "github.com/openshift/client-go/oauth/clientset/versioned/fake"
	userfake "github.com/openshift/client-go/user/clientset/versioned/fake"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"

	"github.com/openshift/oauth-apiserver/pkg/tokenreviews/tokenvalidation/usercache"
	tokenvalidators "github.com/openshift/oauth-apiserver/pkg/tokenreviews/tokenvalidation/validators"
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
	fakeKubeClient := corefake.NewSimpleClientset()
	fakeUserClient := userfake.NewSimpleClientset(&userv1.User{ObjectMeta: metav1.ObjectMeta{Name: "foo", UID: "bar2"}})

	bootstrapDataGetter := bootstrap.NewBootstrapUserDataGetter(fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1())

	tokenAuthenticator := NewTokenAuthenticator(fakeOAuthClient.OauthV1().OAuthAccessTokens(), bootstrapDataGetter, fakeUserClient.UserV1().Users(), NoopGroupMapper{}, tokenvalidators.NewUIDValidator())

	userInfo, err := tokenAuthenticator.gatherUserInfo(context.TODO(), "token")
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
	fakeKubeClient := corefake.NewSimpleClientset()

	bootstrapDataGetter := bootstrap.NewBootstrapUserDataGetter(fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1())

	tokenAuthenticator := NewTokenAuthenticator(fakeOAuthClient.OauthV1().OAuthAccessTokens(), bootstrapDataGetter, fakeUserClient.UserV1().Users(), NoopGroupMapper{})

	userInfo, err := tokenAuthenticator.gatherUserInfo(context.TODO(), "token")
	if err != errLookup {
		t.Error("Expected not found error to be suppressed with lookup error")
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}

func TestAuthenticateTokenOtherGetErrorSuppressed(t *testing.T) {
	fakeOAuthClient := oauthfake.NewSimpleClientset()
	fakeKubeClient := corefake.NewSimpleClientset()
	bootstrapDataGetter := bootstrap.NewBootstrapUserDataGetter(fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1())

	fakeOAuthClient.PrependReactor("get", "oauthaccesstokens", func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, errors.New("get error")
	})
	fakeUserClient := userfake.NewSimpleClientset()
	tokenAuthenticator := NewTokenAuthenticator(fakeOAuthClient.OauthV1().OAuthAccessTokens(), bootstrapDataGetter, fakeUserClient.UserV1().Users(), NoopGroupMapper{})

	userInfo, err := tokenAuthenticator.gatherUserInfo(context.TODO(), "token")
	if err != errLookup {
		t.Error("Expected custom get error to be suppressed with lookup error")
	}
	if userInfo != nil {
		t.Errorf("Unexpected user: %v", userInfo)
	}
}

func TestTokenAuthenticator(t *testing.T) {
	tests := []struct {
		name                string
		audiences           authenticator.Audiences
		accesstoken         *oauthv1.OAuthAccessToken
		user                *userv1.User
		reviewedToken       *string
		expectedResponse    *authenticator.Response
		expectedError       string
		expectAuthenticated bool
	}{
		{
			name:      "no authorization header",
			audiences: authenticator.Audiences{"someaud"},
		},
		{
			name:          "empty token",
			reviewedToken: sptr(""),
			audiences:     authenticator.Audiences{"someaud"},
		},
		{
			name: "non-existent user",
			accesstoken: &oauthv1.OAuthAccessToken{
				ObjectMeta: metav1.ObjectMeta{Name: "atokencreatedmanuallybymetyping"},
				UserName:   "pepa",
				UserUID:    "some-uid",
			},
			user: &userv1.User{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tonda",
					UID:  "tonda-uid",
				},
			},
			reviewedToken: sptr("atokencreatedmanuallybymetyping"),
			expectedError: `users.user.openshift.io "pepa" not found`,
		},
		{
			name: "non-existent token",
			accesstoken: &oauthv1.OAuthAccessToken{
				ObjectMeta: metav1.ObjectMeta{Name: "adifferenttokenfromtheoneintherequest"},
				UserName:   "jenda",
				UserUID:    "some-uid",
				Scopes:     []string{"user:check-access"},
			},
			user: &userv1.User{
				ObjectMeta: metav1.ObjectMeta{
					Name: "jenda",
					UID:  "some-uid",
				},
			},
			reviewedToken: sptr("sometokenthatiscertainlynotpresent"),
			expectedError: "token lookup failed",
		},
		{
			name: "invalid user UID in the token",
			accesstoken: &oauthv1.OAuthAccessToken{
				ObjectMeta: metav1.ObjectMeta{Name: "atokencreatedmanuallybymetyping"},
				UserName:   "usertypek",
				UserUID:    "weird-uid",
				Scopes:     []string{"user:full"},
			},
			user: &userv1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "usertypek"},
			},
			reviewedToken: sptr("atokencreatedmanuallybymetyping"),
			audiences:     authenticator.Audiences{"someaud"},
			expectedError: "user.UID () does not match token.userUID (weird-uid)",
		},
		{
			name: "valid token review",
			accesstoken: &oauthv1.OAuthAccessToken{
				ObjectMeta: metav1.ObjectMeta{Name: "atokencreatedmanuallybymetyping"},
				UserName:   "usertypek",
				UserUID:    "some-uid",
				Scopes:     []string{"user:full"},
			},
			user: &userv1.User{
				ObjectMeta: metav1.ObjectMeta{
					Name: "usertypek",
					UID:  "some-uid",
				},
			},
			reviewedToken: sptr("atokencreatedmanuallybymetyping"),
			expectedResponse: &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   "usertypek",
					UID:    "some-uid",
					Groups: []string{"system:authenticated:oauth"},
					Extra: map[string][]string{
						"scopes.authorization.openshift.io": {"user:full"},
					},
				},
			},
			expectAuthenticated: true,
		},
		{
			name: "valid token review with audiences",
			accesstoken: &oauthv1.OAuthAccessToken{
				ObjectMeta: metav1.ObjectMeta{Name: "atokencreatedmanuallybymetyping"},
				UserName:   "usertypek",
				UserUID:    "some-uid",
				Scopes:     []string{"user:full"},
			},
			user: &userv1.User{
				ObjectMeta: metav1.ObjectMeta{
					Name: "usertypek",
					UID:  "some-uid",
				},
			},
			reviewedToken: sptr("atokencreatedmanuallybymetyping"),
			audiences:     authenticator.Audiences{"someaud", "someotheraud"},
			expectedResponse: &authenticator.Response{
				Audiences: authenticator.Audiences{"someaud", "someotheraud"},
				User: &user.DefaultInfo{
					Name:   "usertypek",
					UID:    "some-uid",
					Groups: []string{"system:authenticated:oauth"},
					Extra: map[string][]string{
						"scopes.authorization.openshift.io": {"user:full"},
					},
				},
			},
			expectAuthenticated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://localhost", nil)
			if tt.reviewedToken != nil {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", *tt.reviewedToken))
			}
			if tt.audiences != nil {
				req = req.WithContext(authenticator.WithAudiences(req.Context(), tt.audiences))
			}

			users := []runtime.Object{}
			if tt.user != nil {
				users = append(users, tt.user)
			}
			tokens := []runtime.Object{}
			if tt.accesstoken != nil {
				tokens = append(tokens, tt.accesstoken)
			}

			userClient := userfake.NewSimpleClientset(users...)
			userInformer := userinformer.NewSharedInformerFactory(userClient, time.Second*60)
			if err := userInformer.User().V1().Groups().Informer().AddIndexers(cache.Indexers{
				usercache.ByUserIndexName: usercache.ByUserIndexKeys,
			}); err != nil {
				t.Fatalf("failed to create user index: %v", err)
			}

			h := TokenAuthenticator{
				accessTokenClient: oauthfake.NewSimpleClientset(tokens...).OauthV1().OAuthAccessTokens(),
				userClient:        userClient.UserV1().Users(),
				groupMapper:       usercache.NewGroupCache(userInformer.User().V1().Groups()),
				// testing just a single validator to prove errors propagate
				validators: tokenvalidators.OAuthTokenValidators{tokenvalidators.NewUIDValidator()},
			}
			gotResponse, authenticated, err := h.AuthenticateRequest(req)

			if err != nil {
				if len(tt.expectedError) == 0 {
					t.Errorf("expected no error, got %v", err)
				} else if tt.expectedError != err.Error() {
					t.Errorf("expected error %q, got %q", tt.expectedError, err.Error())
				}
			}

			if len(tt.expectedError) > 0 && err == nil {
				t.Errorf("expected error %q, but error is nil", tt.expectedError)
			}

			if tt.expectAuthenticated != authenticated {
				t.Errorf("expected authenticated: %v, got %v", tt.expectAuthenticated, authenticated)
			}

			if !equality.Semantic.DeepEqual(tt.expectedResponse, gotResponse) {
				t.Errorf("expected != got: %s", diff.ObjectDiff(tt.expectedResponse, gotResponse))
			}
		})
	}
}

func sptr(s string) *string {
	return &s
}
