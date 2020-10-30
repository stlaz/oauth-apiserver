package tokenvalidation

import (
	"time"

	"github.com/emicklei/go-restful"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	genericapiserver "k8s.io/apiserver/pkg/server"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	oauthclients "github.com/openshift/client-go/oauth/clientset/versioned"
	oauthinformer "github.com/openshift/client-go/oauth/informers/externalversions"
	userclients "github.com/openshift/client-go/user/clientset/versioned"
	userinformer "github.com/openshift/client-go/user/informers/externalversions"
	bootstrap "github.com/openshift/library-go/pkg/authentication/bootstrapauthenticator"

	"github.com/openshift/oauth-apiserver/pkg/tokenvalidation/usercache"
	tokenvalidators "github.com/openshift/oauth-apiserver/pkg/tokenvalidation/validators"
)

const (
	minimumInactivityTimeoutSeconds = 300
	defaultInformerResyncPeriod     = 10 * time.Minute
)

var (
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)
	encoder = codecs.LegacyCodec(authenticationv1.SchemeGroupVersion)
)

func init() {
	utilruntime.Must(authenticationv1.AddToScheme(scheme))
}

type ExtraConfig struct {
	AccessTokenInactivityTimeout time.Duration
}

type TokenValidationServerConfig struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type TokenValidationServer struct {
	GenericAPIServer             *genericapiserver.GenericAPIServer
	AccessTokenInactivityTimeout time.Duration
	kubeAPIServerClientConfig    *restclient.Config
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig

	ExtraConfig               *ExtraConfig
	kubeAPIServerClientConfig *restclient.Config
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *TokenValidationServerConfig) Complete() completedConfig {
	cfg := completedConfig{
		GenericConfig:             c.GenericConfig.Complete(),
		ExtraConfig:               &c.ExtraConfig,
		kubeAPIServerClientConfig: c.GenericConfig.ClientConfig,
	}

	return cfg
}

// New returns a new instance of TokenValidationServer from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*TokenValidationServer, error) {
	genericServer, err := c.GenericConfig.New("oauth.openshift.io-tokenvalidation", delegationTarget)
	if err != nil {
		return nil, err
	}

	s := &TokenValidationServer{
		GenericAPIServer:             genericServer,
		AccessTokenInactivityTimeout: c.ExtraConfig.AccessTokenInactivityTimeout,
		kubeAPIServerClientConfig:    c.kubeAPIServerClientConfig,
	}

	s.installTokenValidation()

	return s, nil
}

func (s *TokenValidationServer) installTokenValidation() error {
	// build clients
	userClient, err := userclients.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		return err
	}

	oauthClient, err := oauthclients.NewForConfig(s.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		return err
	}

	corev1Client, err := corev1.NewForConfig(s.kubeAPIServerClientConfig)
	if err != nil {
		return err
	}
	bootstrapUserDataGetter := bootstrap.NewBootstrapUserDataGetter(corev1Client, corev1Client)

	// create informer for the users to be used in user <-> groups mapping
	userInformer := userinformer.NewSharedInformerFactory(userClient, defaultInformerResyncPeriod)
	if err := userInformer.User().V1().Groups().Informer().AddIndexers(cache.Indexers{
		usercache.ByUserIndexName: usercache.ByUserIndexKeys,
	}); err != nil {
		return err
	}

	groupMapper := usercache.NewGroupCache(userInformer.User().V1().Groups())
	oauthInformer := oauthinformer.NewSharedInformerFactory(oauthClient, defaultInformerResyncPeriod)

	timeoutValidator := tokenvalidators.NewTimeoutValidator(
		oauthClient.OauthV1().OAuthAccessTokens(),
		oauthInformer.Oauth().V1().OAuthClients().Lister(),
		s.AccessTokenInactivityTimeout,
		minimumInactivityTimeoutSeconds)

	s.GenericAPIServer.AddPostStartHookOrDie("openshift.io-StartUserInformer", func(ctx genericapiserver.PostStartHookContext) error {
		go userInformer.Start(ctx.StopCh)
		return nil
	})
	s.GenericAPIServer.AddPostStartHookOrDie("openshift.io-StartOAuthInformer", func(ctx genericapiserver.PostStartHookContext) error {
		go oauthInformer.Start(ctx.StopCh)
		return nil
	})
	s.GenericAPIServer.AddPostStartHookOrDie("openshift.io-StartTokenTimeoutUpdater", func(ctx genericapiserver.PostStartHookContext) error {
		go timeoutValidator.Run(ctx.StopCh)
		return nil
	})

	validationHandler := NewTokenValidationHandler(
		oauthClient.OauthV1().OAuthAccessTokens(), bootstrapUserDataGetter, userClient.UserV1().Users(), groupMapper,
		tokenvalidators.NewExpirationValidator(), tokenvalidators.NewUIDValidator(), timeoutValidator)

	// create the validator service and add it to the the handler chain
	validatorService := new(restful.WebService).
		Produces(restful.MIME_JSON).
		Consumes(restful.MIME_JSON)

	validatorService.Path("/tokenvalidation").Route(
		validatorService.POST("").
			To(validationHandler.ServeHTTP).
			Doc("validates tokens for OpenShift authentication").
			Operation("getOpenShiftTokenValidationResponse"),
	)

	s.GenericAPIServer.Handler.GoRestfulContainer.Add(validatorService)

	return nil
}
