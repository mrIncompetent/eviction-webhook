package admission

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/munnerz/goautoneg"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"

	loghelper "github.com/mrincompetent/eviction-webhook/pkg/log"
)

type Server struct {
	codecs runtime.NegotiatedSerializer
}

func NewServer(scheme *runtime.Scheme) *Server {
	codecs := serializer.NewCodecFactory(scheme)
	return &Server{
		codecs: codecs,
	}
}

type Handler func(context.Context, *zap.Logger, *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error)

func (s *Server) HandleV1AdmissionReview(handleReview Handler) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		log := loghelper.FromContext(request.Context())

		if request.Body == nil {
			http.Error(writer, "No request body given", http.StatusBadRequest)
			return
		}

		admissionReview := &admissionv1.AdmissionReview{}
		if err := s.decodeRequest(request, admissionReview); err != nil {
			http.Error(writer, fmt.Sprintf("failed to decode request: %v", err), http.StatusBadRequest)
			return
		}

		if admissionReview.Request == nil {
			http.Error(writer, "no request defined in admission review", http.StatusBadRequest)
			return
		}

		response, err := handleReview(request.Context(), log.With(zap.Any("admission-review", admissionReview)), admissionReview.Request)
		if err != nil {
			http.Error(writer, fmt.Sprintf("failed to handle review: %v", err), http.StatusInternalServerError)
			return
		}

		admissionReview.Response = response
		admissionReview.Response.UID = admissionReview.Request.UID

		if err := s.encodeResponse(request, admissionReview, writer); err != nil {
			http.Error(writer, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
			return
		}
	}
}

func (s *Server) decodeRequest(request *http.Request, into runtime.Object) error {
	serializerInfo, err := serializerInfoForMediaType(s.codecs, request.Header.Get("Content-Type"))
	if err != nil {
		return fmt.Errorf("failed to find serializer for content-type: %w", err)
	}

	data, err := io.ReadAll(request.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	if _, _, err := serializerInfo.Serializer.Decode(data, nil, into); err != nil {
		return fmt.Errorf("failed to encode object: %w", err)
	}

	return nil
}

func (s *Server) encodeResponse(request *http.Request, obj runtime.Object, writer http.ResponseWriter) error {
	acceptType := request.Header.Get("Accept")
	if acceptType == "" {
		acceptType = runtime.ContentTypeJSON
	}

	supportedMediaTypes := s.codecs.SupportedMediaTypes()
	clauses := goautoneg.ParseAccept(acceptType)
	for i := range clauses {
		clause := &clauses[i]
		for i := range supportedMediaTypes {
			accepts := &supportedMediaTypes[i]
			switch {
			case clause.Type == accepts.MediaTypeType && clause.SubType == accepts.MediaTypeSubType,
				clause.Type == accepts.MediaTypeType && clause.SubType == "*",
				clause.Type == "*" && clause.SubType == "*":

				writer.Header().Set("Content-Type", accepts.MediaType)
				serializerInfo, err := serializerInfoForMediaType(s.codecs, accepts.MediaType)
				if err != nil {
					return fmt.Errorf("failed to find serializer for accept type: %w", err)
				}

				if err := serializerInfo.Serializer.Encode(obj, writer); err != nil {
					return fmt.Errorf("failed to encode object: %w", err)
				}

				return nil
			}
		}
	}

	return unsupportedMediaTypeError{
		availableMediaTypes: supportedMediaTypes,
		mediaType:           acceptType,
	}
}

func serializerInfoForMediaType(codecs runtime.NegotiatedSerializer, mediaType string) (runtime.SerializerInfo, error) {
	mediaType, _, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return runtime.SerializerInfo{}, fmt.Errorf("failed to parse media type '%s': %w", mediaType, err)
	}

	supportedMediaTypes := codecs.SupportedMediaTypes()
	for i := range supportedMediaTypes {
		if supportedMediaTypes[i].MediaType == mediaType {
			return supportedMediaTypes[i], nil
		}
	}

	return runtime.SerializerInfo{}, unsupportedMediaTypeError{
		availableMediaTypes: supportedMediaTypes,
		mediaType:           mediaType,
	}
}

type unsupportedMediaTypeError struct {
	availableMediaTypes []runtime.SerializerInfo
	mediaType           string
}

func (u unsupportedMediaTypeError) Error() string {
	types := sets.NewString()
	for i := range u.availableMediaTypes {
		types.Insert(u.availableMediaTypes[i].MediaType)
	}

	return fmt.Sprintf("unsupported media type %q, available media types: [%s]", u.mediaType, strings.Join(types.List(), ", "))
}
