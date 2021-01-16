# Kubernetes mutatingwebhook to inject secrets in manifests
The project is intended updated the images for the pods from docker.io to some other domain. The Kubernetes webhook has been developed considering the functionality of harbor and leverage the harbor proxy to fetch the images from the dockerhub. One can specify the custom/private/proxy image endpoint and the additional path to be used for proxy and the webhook will then replace the image to be fetched from the specified path.

### In order to skip image patching for specific pods use the following annotations(in pods specification)
```yaml
annotations:
  admissionWebhookAnnotationSkipKey: "true" 
```

### Deployment
Helm Chart can be used to deploy the webhook as per the available values


### Following environment variables should be configure the deployment
|ENV |Description| Required
|:---|---|---|
TOKEN | If a token to access is to be specified explicitly | False (Will be fetched when kubernetes auth will be used)
ROLE | Role configured against kubernetes auth. In this case deployment will utilize Service Account token to access vault using kubernetes auth method | False (Only with kubernetes auth method)
REGISTRY | Docker Registry URL address(private.registry.io)| True
PUBLIC_PROJECT | Path of the public project which should be referred in case the docker image doesnt have an org (eg nginx) | True
REGISTRY_PROXY_NAME | CProxy project name configured on harbor. | True