package tokenvalidation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	kuser "k8s.io/apiserver/pkg/authentication/user"

	authorizationv1 "github.com/openshift/api/authorization/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userv1client "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"

	tokenvalidators "github.com/openshift/oauth-apiserver/pkg/tokenreviews/tokenvalidation/validators"
)

const (
	clusterAdminGroup       = "system:cluster-admins"
	authenticatedOAuthGroup = "system:authenticated:oauth"

	sha256Prefix = "sha256~"
)

var errLookup = errors.New("token lookup failed")

var _ authenticator.Request = &TokenAuthenticator{}

type TokenAuthenticator struct {
	accessTokenClient   oauthv1client.OAuthAccessTokenInterface
	userClient          userv1client.UserInterface
	bootstrapUserGetter bootstrap.BootstrapUserDataGetter
	groupMapper         UserToGroupMapper

	validators tokenvalidators.OAuthTokenValidator
}

func NewTokenAuthenticator(
	accessTokenClient oauthv1client.OAuthAccessTokenInterface,
	bootstrapUserGetter bootstrap.BootstrapUserDataGetter,
	userClient userv1client.UserInterface,
	groupMapper UserToGroupMapper,
	validators ...tokenvalidators.OAuthTokenValidator,
) *TokenAuthenticator {
	return &TokenAuthenticator{
		accessTokenClient:   accessTokenClient,
		userClient:          userClient,
		bootstrapUserGetter: bootstrapUserGetter,
		groupMapper:         groupMapper,

		validators: tokenvalidators.OAuthTokenValidators(validators),
	}
}

func (h *TokenAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	authorizationHeader := strings.TrimSpace(req.Header.Get("Authorization"))
	if len(authorizationHeader) == 0 {
		return nil, false, nil
	}

	authzHeaderSplit := strings.Split(authorizationHeader, " ")
	if len(authzHeaderSplit) < 2 || strings.ToLower(authzHeaderSplit[0]) != "bearer" {
		return nil, false, nil
	}

	tokenString := authzHeaderSplit[1]
	if len(tokenString) == 0 {
		return nil, false, nil
	}

	// normalize to sha256 form if sha256 token
	if strings.HasPrefix(tokenString, sha256Prefix) {
		h := sha256.Sum256([]byte(strings.TrimPrefix(tokenString, sha256Prefix)))
		tokenString = sha256Prefix + base64.RawURLEncoding.EncodeToString(h[:])
	}

	userInfo, err := h.gatherUserInfo(context.TODO(), tokenString)
	if err != nil {
		return nil, false, err
	}

	reqAuds, _ := authenticator.AudiencesFrom(req.Context())

	return &authenticator.Response{
		User:      userInfo,
		Audiences: reqAuds, // OpenShift does not deal with audiences in its access tokens, send the audiences that were expected
	}, true, nil
}

func (h *TokenAuthenticator) gatherUserInfo(ctx context.Context, tokenName string) (user.Info, error) {
	token, err := h.accessTokenClient.Get(ctx, tokenName, metav1.GetOptions{})
	if err != nil {
		return nil, errLookup // mask the error so we do not leak token data in logs
	}

	var user *userv1.User
	var groupNames []string
	// the bootstrap user is special-cased in authentication
	if token.UserName == bootstrap.BootstrapUser {
		user, groupNames, err = h.getBootstrapUser(token)
	} else {
		user, groupNames, err = h.getOpenShiftUser(ctx, token)
	}

	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("no such user")
	}

	return &kuser.DefaultInfo{
		Name:   user.Name,
		UID:    string(user.UID),
		Groups: groupNames,
		Extra: map[string][]string{
			authorizationv1.ScopesKey: token.Scopes,
		},
	}, nil
}

func (h *TokenAuthenticator) getBootstrapUser(token *oauthv1.OAuthAccessToken) (*userv1.User, []string, error) {
	data, ok, err := h.bootstrapUserGetter.Get()
	if err != nil || !ok {
		return nil, nil, err
	}

	// this allows us to reuse existing validators
	// since the uid is based on the secret, if the secret changes, all
	// tokens issued for the bootstrap user before that change stop working
	fakeUser := &userv1.User{
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID(data.UID),
			Name: "kube:admin",
		},
	}

	if err := h.validators.Validate(token, fakeUser); err != nil {
		return nil, nil, err
	}

	// we cannot use SystemPrivilegedGroup because it cannot be properly scoped.
	// see openshift/origin#18922 and how loopback connections are handled upstream via AuthorizeClientBearerToken.
	// api aggregation with delegated authorization makes this impossible to control, see WithAlwaysAllowGroups.
	// an openshift specific cluster role binding binds ClusterAdminGroup to the cluster role cluster-admin.
	// thus this group is authorized to do everything via RBAC.
	// this does make the bootstrap user susceptible to anything that causes the RBAC authorizer to fail.
	// this is a safe trade-off because scopes must always be evaluated before RBAC for them to work at all.
	// a failure in that logic means scopes are broken instead of a specific failure related to the bootstrap user.
	// if this becomes a problem in the future, we could generate a custom extra value based on the secret content
	// and store it in BootstrapUserData, similar to how UID is calculated.  this extra value would then be wired
	// to a custom authorizer that allows all actions.  the problem with such an approach is that since we do not
	// allow remote authorizers in OpenShift, the BootstrapUserDataGetter logic would have to be shared between the
	// the kube api server and osin instead of being an implementation detail hidden inside of osin.  currently the
	// only shared code is the value of the BootstrapUser constant (since it is special cased in validation)
	return fakeUser, []string{clusterAdminGroup}, nil
}

func (h *TokenAuthenticator) getOpenShiftUser(ctx context.Context, token *oauthv1.OAuthAccessToken) (*userv1.User, []string, error) {
	user, err := h.userClient.Get(ctx, token.UserName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	if err := h.validators.Validate(token, user); err != nil {
		return nil, nil, err
	}

	groups, err := h.groupMapper.GroupsFor(user.Name)
	if err != nil {
		return nil, nil, err
	}
	groupNames := make([]string, 0, len(groups))
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}

	// append system:authenticated:oauth group because if you have an OAuth
	// bearer token, you're a human (usually)
	return user, append(groupNames, authenticatedOAuthGroup), nil
}
