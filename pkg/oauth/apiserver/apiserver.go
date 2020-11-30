package apiserver

import (
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/emicklei/go-restful"
	oauthapiv1 "github.com/openshift/api/oauth/v1"
	oauthclients "github.com/openshift/client-go/oauth/clientset/versioned"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions"
	routeclient "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	userclients "github.com/openshift/client-go/user/clientset/versioned"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	"github.com/openshift/library-go/pkg/oauth/oauthserviceaccountclient"

	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"
	accesstokenetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthaccesstoken/etcd"
	authorizetokenetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthauthorizetoken/etcd"
	clientetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthclient/etcd"
	clientauthetcd "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthclientauthorization/etcd"
	oauthtokenreviewrest "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/oauthtokenreview/rest"
	useroauthaccesstokensdelegate "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver/registry/useroauthaccesstokens/delegate"
	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
	tokenvalidation "github.com/openshift/oauth-apiserver/pkg/tokenvalidation"
	"github.com/openshift/oauth-apiserver/pkg/tokenvalidation/usercache"
	tokenvalidators "github.com/openshift/oauth-apiserver/pkg/tokenvalidation/validators"
)

const (
	defaultInformerResyncPeriod     = 10 * time.Minute
	minimumInactivityTimeoutSeconds = 300
)

type ExtraConfig struct {
	ServiceAccountMethod string

	makeV1Storage      sync.Once
	v1Storage          map[string]rest.Storage
	v1StorageErr       error
	postStartHooks     map[string]genericapiserver.PostStartHookFunc
	tokenReviewService *restful.WebService

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

	v1Storage, tokenReviewService, postStartHooks, err := c.V1RESTStorage()
	if err != nil {
		return nil, err
	}

	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(oauthapiv1.GroupName, serverscheme.Scheme, metav1.ParameterCodec, serverscheme.Codecs)
	apiGroupInfo.VersionedResourcesStorageMap[oauthapiv1.SchemeGroupVersion.Version] = v1Storage
	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, err
	}

	s.GenericAPIServer.Handler.GoRestfulContainer.Add(tokenReviewService)
	for hookname := range postStartHooks {
		s.GenericAPIServer.AddPostStartHookOrDie(hookname, c.ExtraConfig.postStartHooks[hookname])
	}

	return s, nil
}

func (c *completedConfig) V1RESTStorage() (map[string]rest.Storage, *restful.WebService, map[string]genericapiserver.PostStartHookFunc, error) {
	c.ExtraConfig.makeV1Storage.Do(func() {
		c.ExtraConfig.v1Storage, c.ExtraConfig.tokenReviewService, c.ExtraConfig.postStartHooks, c.ExtraConfig.v1StorageErr = c.newV1RESTStorage()
	})

	return c.ExtraConfig.v1Storage, c.ExtraConfig.tokenReviewService, c.ExtraConfig.postStartHooks, c.ExtraConfig.v1StorageErr
}

func (c *completedConfig) tokenReviewStorage(
	corev1Client corev1.CoreV1Interface,
	oauthClient *oauthclients.Clientset,
	userClient *userclients.Clientset,
) (*restful.WebService, map[string]genericapiserver.PostStartHookFunc, error) {
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

	if c.ExtraConfig.postStartHooks == nil {
		c.ExtraConfig.postStartHooks = map[string]genericapiserver.PostStartHookFunc{}
	}

	c.ExtraConfig.postStartHooks["openshift.io-StartUserInformer"] = func(ctx genericapiserver.PostStartHookContext) error {
		go userInformer.Start(ctx.StopCh)
		return nil
	}
	c.ExtraConfig.postStartHooks["openshift.io-StartOAuthInformer"] = func(ctx genericapiserver.PostStartHookContext) error {
		go oauthInformer.Start(ctx.StopCh)
		return nil
	}
	c.ExtraConfig.postStartHooks["openshift.io-StartTokenTimeoutUpdater"] = func(ctx genericapiserver.PostStartHookContext) error {
		go timeoutValidator.Run(ctx.StopCh)
		return nil
	}

	tokenAuthenticator := tokenvalidation.NewTokenValidationHandler(
		oauthClient.OauthV1().OAuthAccessTokens(), bootstrapUserDataGetter, userClient.UserV1().Users(), groupMapper,
		tokenvalidators.NewExpirationValidator(), tokenvalidators.NewUIDValidator(), timeoutValidator)

	tokenReviewWrapper := oauthtokenreviewrest.NewTokenReviewRESTWrapper(tokenAuthenticator)

	// create the validator service and add it to the the handler chain
	validatorService := new(restful.WebService).
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON)

	validatorService.Path("/tokenvalidation").Route(
		validatorService.POST("").
			To(tokenReviewWrapper.ServeHTTP).
			Doc("validates tokens for OpenShift authentication").
			Operation("getOpenShiftTokenValidationResponse"),
	)

	return validatorService, c.ExtraConfig.postStartHooks, nil
}

func (c *completedConfig) newV1RESTStorage() (map[string]rest.Storage, *restful.WebService, map[string]genericapiserver.PostStartHookFunc, error) {
	clientStorage, err := clientetcd.NewREST(c.GenericConfig.RESTOptionsGetter)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}

	// If OAuth is disabled, set the strategy to Deny
	saAccountGrantMethod := oauthapiv1.GrantHandlerDeny
	if len(c.ExtraConfig.ServiceAccountMethod) > 0 {
		// Otherwise, take the value provided in master-config.yaml
		saAccountGrantMethod = oauthapiv1.GrantHandlerType(c.ExtraConfig.ServiceAccountMethod)
	}

	oauthClient, err := oauthclients.NewForConfig(c.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	userClient, err := userclients.NewForConfig(c.GenericConfig.LoopbackClientConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	routeClient, err := routeclient.NewForConfig(c.kubeAPIServerClientConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	coreV1Client, err := corev1.NewForConfig(c.kubeAPIServerClientConfig)
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	accessTokenStorage, err := accesstokenetcd.NewREST(c.GenericConfig.RESTOptionsGetter, combinedOAuthClientGetter)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	clientAuthorizationStorage, err := clientauthetcd.NewREST(c.GenericConfig.RESTOptionsGetter, combinedOAuthClientGetter)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	tokenReviewStorage, postStartHooks, err := c.tokenReviewStorage(coreV1Client, oauthClient, userClient)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}
	userOAuthAccessTokensDelegate, err := useroauthaccesstokensdelegate.NewREST(accessTokenStorage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error building REST storage: %v", err)
	}

	v1Storage := map[string]rest.Storage{}
	v1Storage["oAuthAuthorizeTokens"] = authorizeTokenStorage
	v1Storage["oAuthAccessTokens"] = accessTokenStorage
	v1Storage["oAuthClients"] = clientStorage
	v1Storage["oAuthClientAuthorizations"] = clientAuthorizationStorage
	v1Storage["userOAuthAccessTokens"] = userOAuthAccessTokensDelegate
	return v1Storage, tokenReviewStorage, postStartHooks, nil
}
