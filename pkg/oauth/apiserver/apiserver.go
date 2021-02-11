package apiserver

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	oauthapiv1 "github.com/openshift/api/oauth/v1"
	oauthclients "github.com/openshift/client-go/oauth/clientset/versioned"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	"github.com/openshift/library-go/pkg/oauth/oauthserviceaccountclient"

	accesstokenetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthaccesstoken/etcd"
	authorizetokenetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthauthorizetoken/etcd"
	clientetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthclient/etcd"
	clientauthetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthclientauthorization/etcd"
	tokenreviews "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/tokenreviews"
	useroauthaccesstokensdelegate "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/useroauthaccesstokens/delegate"
	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
	"github.com/openshift/oauth-apiserver/pkg/tokenreviews/tokenvalidation"
	"github.com/openshift/oauth-apiserver/pkg/tokenreviews/tokenvalidation/usercache"
	tokenvalidators "github.com/openshift/oauth-apiserver/pkg/tokenreviews/tokenvalidation/validators"
)

const (
	defaultInformerResyncPeriod     = 10 * time.Minute
	minimumInactivityTimeoutSeconds = 300
)

type ExtraConfig struct {
	ServiceAccountMethod         string
	AccessTokenInactivityTimeout time.Duration
}

type OAuthAPIServerConfig struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type OAuthAPIServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig             genericapiserver.CompletedConfig
	ExtraConfig               *ExtraConfig
	kubeAPIServerClientConfig *restclient.Config
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *OAuthAPIServerConfig) Complete() completedConfig {
	cfg := completedConfig{
		GenericConfig:             c.GenericConfig.Complete(),
		ExtraConfig:               &c.ExtraConfig,
		kubeAPIServerClientConfig: c.GenericConfig.ClientConfig,
	}

	return cfg
}

// New returns a new instance of OAuthAPIServer from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*OAuthAPIServer, error) {
	genericServer, err := c.GenericConfig.New("oauth.openshift.io-apiserver", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &OAuthAPIServer{
		GenericAPIServer: genericServer,
	}

	v1Storage, postStartHooks, err := c.newV1RESTStorage()
	if err != nil {
		return nil, err
	}

	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(oauthapiv1.GroupName, serverscheme.Scheme, metav1.ParameterCodec, serverscheme.Codecs)
	apiGroupInfo.VersionedResourcesStorageMap[oauthapiv1.SchemeGroupVersion.Version] = v1Storage
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	for hookname := range postStartHooks {
		s.GenericAPIServer.AddPostStartHookOrDie(hookname, postStartHooks[hookname])
	}

	return s, nil
}

func (c *completedConfig) newV1RESTStorage() (map[string]rest.Storage, map[string]genericapiserver.PostStartHookFunc, error) {
	clientStorage, err := clientetcd.NewREST(c.GenericConfig.RESTOptionsGetter)
	if err != nil {
		return nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}

	// If OAuth is disabled, set the strategy to Deny
	saAccountGrantMethod := oauthapiv1.GrantHandlerDeny
	if len(c.ExtraConfig.ServiceAccountMethod) > 0 {
		// Otherwise, take the value provided in master-config.yaml
		saAccountGrantMethod = oauthapiv1.GrantHandlerType(c.ExtraConfig.ServiceAccountMethod)
	}

	oauthClient, err := oauthclients.NewForConfig(c.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, nil, err
	}
	routeClient, err := routeclient.NewForConfig(c.kubeAPIServerClientConfig)
	if err != nil {
		return nil, nil, err
	}
	coreV1Client, err := corev1.NewForConfig(c.kubeAPIServerClientConfig)
	if err != nil {
		return nil, nil, err
	}
	userClient, err := userclient.NewForConfig(c.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, nil, err
	}

	combinedOAuthClientGetter := oauthserviceaccountclient.NewServiceAccountOAuthClientGetter(
		coreV1Client,
		coreV1Client,
		coreV1Client.Events(""),
		routeClient,
		oauthClient.OauthV1().OAuthClients(),
		saAccountGrantMethod,
	)
	authorizeTokenStorage, err := authorizetokenetcd.NewREST(c.GenericConfig.RESTOptionsGetter, combinedOAuthClientGetter)
	if err != nil {
		return nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	accessTokenStorage, err := accesstokenetcd.NewREST(c.GenericConfig.RESTOptionsGetter, combinedOAuthClientGetter)
	if err != nil {
		return nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	clientAuthorizationStorage, err := clientauthetcd.NewREST(c.GenericConfig.RESTOptionsGetter, combinedOAuthClientGetter)
	if err != nil {
		return nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	userOAuthAccessTokensDelegate, err := useroauthaccesstokensdelegate.NewREST(accessTokenStorage)
	if err != nil {
		return nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	tokenReviewStorage, tokenReviewPostStartHooks, err := c.tokenReviewStorage(coreV1Client, oauthClient, userClient)
	if err != nil {
		return nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}

	v1Storage := map[string]rest.Storage{
		"oAuthAuthorizeTokens":      authorizeTokenStorage,
		"oAuthAccessTokens":         accessTokenStorage,
		"oAuthClients":              clientStorage,
		"oAuthClientAuthorizations": clientAuthorizationStorage,
		"userOAuthAccessTokens":     userOAuthAccessTokensDelegate,
		"tokenReviews":              tokenReviewStorage,
	}
	return v1Storage, tokenReviewPostStartHooks, nil
}

func (c *completedConfig) tokenReviewStorage(
	corev1Client corev1.CoreV1Interface,
	oauthClient *oauthclients.Clientset,
	userClient *userclient.Clientset,
) (rest.Storage, map[string]genericapiserver.PostStartHookFunc, error) {
	bootstrapUserDataGetter := bootstrap.NewBootstrapUserDataGetter(corev1Client, corev1Client)

	// create informer for the users to be used in user <-> groups mapping
	userInformer := userinformer.NewSharedInformerFactory(userClient, defaultInformerResyncPeriod)
	if err := userInformer.User().V1().Groups().Informer().AddIndexers(cache.Indexers{
		usercache.ByUserIndexName: usercache.ByUserIndexKeys,
	}); err != nil {
		return nil, nil, err
	}

	groupMapper := usercache.NewGroupCache(userInformer.User().V1().Groups())
	oauthInformer := oauthinformer.NewSharedInformerFactory(oauthClient, defaultInformerResyncPeriod)

	timeoutValidator := tokenvalidators.NewTimeoutValidator(
		oauthClient.OauthV1().OAuthAccessTokens(),
		oauthInformer.Oauth().V1().OAuthClients().Lister(),
		c.ExtraConfig.AccessTokenInactivityTimeout,
		minimumInactivityTimeoutSeconds)

	postStartHooks := map[string]genericapiserver.PostStartHookFunc{}
	postStartHooks["openshift.io-StartUserInformer"] = func(ctx genericapiserver.PostStartHookContext) error {
		go userInformer.Start(ctx.StopCh)
		return nil
	}
	postStartHooks["openshift.io-StartOAuthInformer"] = func(ctx genericapiserver.PostStartHookContext) error {
		go oauthInformer.Start(ctx.StopCh)
		return nil
	}
	postStartHooks["openshift.io-StartTokenTimeoutUpdater"] = func(ctx genericapiserver.PostStartHookContext) error {
		go timeoutValidator.Run(ctx.StopCh)
		return nil
	}

	tokenAuthenticator := tokenvalidation.NewTokenAuthenticator(
		oauthClient.OauthV1().OAuthAccessTokens(), bootstrapUserDataGetter, userClient.UserV1().Users(), groupMapper,
		tokenvalidators.NewExpirationValidator(), tokenvalidators.NewUIDValidator(), timeoutValidator)

	tokenReviewWrapper, err := tokenreviews.NewREST(tokenAuthenticator)

	return tokenReviewWrapper, postStartHooks, err
}
