package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"gopkg.in/yaml.v2"
	av1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme   = runtime.NewScheme()
	codecs          = serializer.NewCodecFactory(runtimeScheme)
	deserializer    = codecs.UniversalDeserializer()
	registryURL     = os.Getenv("REGISTRY")
	publicProject   = os.Getenv("PUBLIC_PROJECT")
	registryProxy   = os.Getenv("REGISTRY_PROXY_NAME")
	istioProxyImage = os.Getenv("ISTIO_PROXY_IMAGE")
	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter   = runtime.ObjectDefaulter(runtimeScheme)
	insecure, _ = strconv.ParseBool(os.Getenv("VAULT_SKIP_VERIFY"))
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationSkipKey   = "bifrost.io/skip-image-injection"
	admissionWebhookAnnotationStatusKey = "bifrost.io/image-injection-status"
	admissionWebhookAnnotationIstio     = "sidecar.istio.io/proxyImage"
)

type WebhookServer struct {
	sidecarConfig *Config
	server        *http.Server
}

type Config struct {
	Containers []corev1.Container `yaml:"containers"`
	Volumes    []corev1.Volume    `yaml:"volumes"`
}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	//_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	//_ = v1.AddToScheme(runtimeScheme)
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, kubeObj *corev1.Pod) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if kubeObj.GetNamespace() == namespace {
			glog.Infof("Skip mutation for %v for it's in special namespace:%v", kubeObj.GetName(), kubeObj.GetNamespace())
			return false
		}
	}

	annotations := kubeObj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		switch strings.ToLower(annotations[admissionWebhookAnnotationSkipKey]) {
		default:
			required = true
		case "y", "yes", "true", "on":
			required = false
		}
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required:%v", kubeObj.GetNamespace(), kubeObj.GetName(), status, required)
	return required
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	if target == nil {
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  "/metadata/annotations",
			Value: added, // strings.Replace(key, "/", "~1", -1), value),
		})
	} else {
		for key, value := range added {
			patch = append(patch, patchOperation{
				Op:    "add",
				Path:  "/metadata/annotations/" + strings.Replace(key, "/", "~1", -1),
				Value: value,
			})
		}
	}
	return patch
}

func patchedImage(reqImage string) string {
	if len(strings.Split(reqImage, "/")) == 1 {
		return registryURL + "/" + registryProxy + "/" + publicProject + "/" + reqImage
	} else if strings.Contains(strings.Split(reqImage, "/")[0], ("docker.io")) {
		if len(strings.Split(reqImage, "/")) == 2 {
			return registryURL + "/" + registryProxy + "/" + publicProject + "/" + strings.SplitN(reqImage, "/", 2)[1]

		} else {
			return registryURL + "/" + registryProxy + "/" + strings.SplitN(reqImage, "/", 2)[1]
		}
	} else if !strings.Contains(strings.Split(reqImage, "/")[0], (".")) {
		return registryURL + "/" + registryProxy + "/" + reqImage
	}
	return reqImage
}

func patchImage(podSpec *corev1.PodSpec) (patch []patchOperation) {

	imagePatch := []patchOperation{}

	for k, v := range podSpec.InitContainers {
		path := fmt.Sprintf("/spec/initContainers/%d/image", k)
		value := patchedImage(v.Image)
		imagePatch = append(imagePatch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	for k, v := range podSpec.Containers {
		path := fmt.Sprintf("/spec/containers/%d/image", k)
		value := patchedImage(v.Image)
		imagePatch = append(imagePatch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}

	return imagePatch
}

func createPatch(kubeObj *corev1.Pod, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation
	patch = append(patch, patchImage(&kubeObj.Spec)...)
	patch = append(patch, updateAnnotation(kubeObj.GetAnnotations(), annotations)...)
	return json.Marshal(patch)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *av1.AdmissionReview) *av1.AdmissionResponse {
	//getVaultConfig()
	req := ar.Request

	//var kubeObj uv1.Unstructured
	var kubeObj corev1.Pod
	r := strings.NewReplacer("\n", "")
	convertedBytes := []byte(r.Replace(string(req.Object.Raw)))

	if err := json.Unmarshal(req.Object.Raw, &kubeObj); err != nil {
		glog.Errorf("Error while unmarshal to Pod")
	}

	if _, _, err := deserializer.Decode(convertedBytes, nil, &kubeObj); err != nil {
		glog.Errorf("Can't decode body: %v", err)
	}

	glog.Infof("Annotations are: %v", kubeObj.GetAnnotations())

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, kubeObj.GetName(), kubeObj.GetGenerateName(), req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &kubeObj) {
		glog.Infof("Skipping mutation for %s/%s%s due to policy check", kubeObj.GetNamespace(), kubeObj.GetName(), kubeObj.GetGenerateName())
		return &av1.AdmissionResponse{
			Allowed: true,
		}
	}

	// Workaround: https://github.com/kubernetes/kubernetes/issues/57982
	//applyDefaultsWorkaround(whsvr.sidecarConfig.Containers, whsvr.sidecarConfig.Volumes)
	annotations := make(map[string]string)
	if len(istioProxyImage) != 0 {
		annotations = map[string]string{admissionWebhookAnnotationStatusKey: "patched",
			admissionWebhookAnnotationIstio: istioProxyImage,
		}

	} else {
		annotations = map[string]string{admissionWebhookAnnotationStatusKey: "patched"}
	}
	patchBytes, err := createPatch(&kubeObj, annotations)
	if err != nil {
		return &av1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &av1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *av1.PatchType {
			pt := av1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *av1.AdmissionResponse
	ar := av1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &av1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := av1.AdmissionReview{}
	admissionReview.APIVersion = "admission.k8s.io/v1"
	admissionReview.Kind = "AdmissionReview"
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	glog.Infof(string(resp))
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
