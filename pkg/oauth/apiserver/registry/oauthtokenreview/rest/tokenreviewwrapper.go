package rest

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/kubernetes/pkg/apis/authentication"
	authenticationv1internal "k8s.io/kubernetes/pkg/apis/authentication/v1"
	ktokenreview "k8s.io/kubernetes/pkg/registry/authentication/tokenreview"
)

var (
	scheme  = runtime.NewScheme()
	codecs  = serializer.NewCodecFactory(scheme)
	encoder = codecs.LegacyCodec(
		authentication.SchemeGroupVersion,
		authenticationv1.SchemeGroupVersion,
	)
)

func init() {
	utilruntime.Must(authentication.AddToScheme(scheme))
	utilruntime.Must(authenticationv1.AddToScheme(scheme))
}

type TokenReviewRESTWrapper struct {
	wrapped *ktokenreview.REST
}

func NewTokenReviewRESTWrapper(authenticator authenticator.Request) *TokenReviewRESTWrapper {
	return &TokenReviewRESTWrapper{
		wrapped: ktokenreview.NewREST(authenticator, []string{}),
	}
}

func (tw *TokenReviewRESTWrapper) ServeHTTP(r *restful.Request, w *restful.Response) {
	tokenReview := &authentication.TokenReview{}

	if err := json.NewDecoder(r.Request.Body).Decode(tokenReview); err != nil {
		handleFailure(w, http.StatusBadRequest, fmt.Sprintf("the input data is not a token review request"))
		return
	}

	obj, err := tw.wrapped.Create(r.Request.Context(), tokenReview, nil, &metav1.CreateOptions{})
	if err != nil {
		apiStatus := responsewriters.ErrorToAPIStatus(err)
		handleFailure(w, (int)(apiStatus.Code), apiStatus.Message)
		return
	}

	tokenReview, ok := obj.(*authentication.TokenReview)
	if !ok {
		handleFailure(w, http.StatusInternalServerError, "the object from the internal storage is not a TokenReview")
		return
	}

	v1tokenReview := &authenticationv1.TokenReview{}
	if err := authenticationv1internal.Convert_authentication_TokenReview_To_v1_TokenReview(tokenReview, v1tokenReview, nil); err != nil {
		handleFailure(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := encoder.Encode(v1tokenReview, w); err != nil {
		handleFailure(w, http.StatusInternalServerError, err.Error())
		return
	}
}

func handleFailure(w *restful.Response, status int, errMsg string) {
	failedReview := authenticationv1.TokenReview{
		Status: authenticationv1.TokenReviewStatus{
			Authenticated: false,
			Error:         errMsg,
		},
	}
	respBytes, err := runtime.Encode(encoder, &failedReview)
	if err != nil {
		w.WriteError(http.StatusInternalServerError, fmt.Errorf("failed to encode authentication failure: %v", err))
		return
	}

	w.WriteHeader(status)
	w.Write(respBytes)
}
