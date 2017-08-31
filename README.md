# UAA Kubernetes OpenID Connect helper

This is a small helper tool that generates a [kubeconfig][kubeconfig] snippet with user credentials to get authenticated via
[Kubernetes OpenID Connect Tokens][k8s-oidc] using [Cloud Foundry UAA][uaa] as the Identity Provider.

Given a `username` and `password` registered at an [UAA][uaa] server, the tool will output the necessary configuration for `kubectl` that you can add to your `~/.kube/config`:

```
# Add the following to your ~/.kube/config
users:
- name: you@yourdomain.com
  user:
    auth-provider:
      name: oidc
      config:
        idp-issuer-url: https://<UAA URL>
        client-id: cf
        client-secret: ""
        id-token: <REDACTED>
        refresh-token: <REDACTED>
```

## Table of Contents

* [Installation](https://github.com/frodenas/uaa-k8s-oidc-helper#installation)
  * [From source](https://github.com/frodenas/uaa-k8s-oidc-helper#from-source)
  * [Docker](https://github.com/frodenas/uaa-k8s-oidc-helper#docker)
* [Usage](https://github.com/frodenas/uaa-k8s-oidc-helper#usage)
  * [Flags](https://github.com/frodenas/uaa-k8s-oidc-helper#flags)
* [OpenID Connect Setup](https://github.com/frodenas/uaa-k8s-oidc-helper#openid-connect-setup)
  * [Kubernetes](https://github.com/frodenas/uaa-k8s-oidc-helper#kubernetes)
  * [UAA](https://github.com/frodenas/uaa-k8s-oidc-helper#uaa)
* [Contributing](https://github.com/frodenas/uaa-k8s-oidc-helper#contributing)
* [License](https://github.com/frodenas/uaa-k8s-oidc-helper#license)
* [Acknowledgements](https://github.com/frodenas/uaa-k8s-oidc-helper#acknowledgements)

## Installation

### From source

Using the standard `go install` (you must have [Go][golang] already installed in your local machine):

```bash
$ go install github.com/frodenas/uaa-k8s-oidc-helper
```

### Docker

To run the helper inside a Docker container, run:

```
$ docker run --rm frodenas/uaa-k8s-oidc-helper <flags>
```
## Usage

```bash
$ uaa-k8s-oidc-helper <flags>
```

### Flags

| Flag | Required | Default | Description |
| ---- | -------- | ------- | ----------- |
| `uaa.url` | Yes | | UAA URL |
| `uaa.username` | Yes |  | UAA Username to generate credentials for |
| `uaa.password` | Yes |  | UAA Password to generate credentials for |
| `uaa.client_id` | No | `cf` | UAA Client ID (must have an `openid` scope) |
| `uaa.client_secret` | No |  | UAA Client Secret |
| `uaa.skip_ssl_verify` | No | `false`  | Disable UAA SSL Verify |

## OpenID Connect Setup

Some steps are required to configure [Kubernetes OpenID Connect][k8s-oidc] to use [Cloud Foundry UAA][uaa] as the Identity Provider:

### Kubernetes

Add the following flags to `kube-apiserver` to configure OpenID Connect:

```
--oidc-issuer-url=https://<UAA URL>/oauth/token \
--oidc-client-id=<Your client ID> \
```

Remember that `<Your client ID>` must have an `openid` scope. If you're using an [UAA][uaa] server deployed as part of a [Cloud Foundry][cloudfoundry] deployment you can use the `cf` client ID.

If the [UAA][uaa] server is using a self-signed certificate, add also the `CA` that signed the certificates:

```
--oidc-ca-file=<path to the CA file> \
```

If you're using an [UAA][uaa] server deployed as part of a [Cloud Foundry][cloudfoundry] deployment with self-signed certificates, remember that the certificate must explicitelly include the `uaa` hostname (ie a certificate for `*.example.com` does NOT include `uaa.system.example.com`, but a `*.system.example.com` is valid).

Also remember to [authorize][k8s-authorization] users to be able to make requests to the the API server:

* If you are using the [ABAC][k8s-abac] authorization method, you can include all `system:authenticated` users to your authorization policy file:

  ```json
  {
    "apiVersion": "abac.authorization.kubernetes.io/v1beta1",
    "kind": "Policy",
    "spec": {
      "user": "*",
      "group": "system:authenticated",
      "apiGroup": "*",
      "namespace": "*",
      "resource": "*",
      "nonResourcePath": "*",
      "readonly": true
    }
  }
  ```

* If you are using the [RBAC][k8s-rbac] authorization method, you must create a `Role` (and/or `ClusterRole`) and a `RoleBinding` (and/or `ClusterRoleBinding`).

Please refer to the [Kubernetes authorization][k8s-authorization] documentation for more details.

### UAA

No special configuration is required for [UAA][uaa]. Only a `client-id` with an `openid` scope must be created.

At the moment of writing these instructions, the current [UAA v45 release][uaa-releases] does not conform to the [OIDC specification][oidc]. This helper tool has been tested using UAA v46 (not yet released).

## Contributing

Refer to the [contributing guidelines][contributing].

## License

Apache License 2.0, see [LICENSE][license].

## Acknowledgements

This tool has heavily inspired by the [k8s-oidc-helper][k8s-oidc-helper].

[cloudfoundry]: https://www.cloudfoundry.org/
[contributing]: https://github.com/frodenas/uaa-k8s-oidc-helper/blob/master/CONTRIBUTING.md
[golang]: https://golang.org/
[license]: https://github.com/frodenas/uaa-k8s-oidc-helper/blob/master/LICENSE
[k8s-abac]: https://kubernetes.io/docs/admin/authorization/abac/
[k8s-authorization]: https://kubernetes.io/docs/admin/authorization/
[k8s-oidc]: https://kubernetes.io/docs/admin/authentication
[k8s-oidc-helper]: https://github.com/micahhausler/k8s-oidc-helper
[k8s-rbac]: https://kubernetes.io/docs/admin/authorization/rbac/
[kubeconfig]: https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/
[oidc]: http://openid.net/connect/
[san]: https://en.wikipedia.org/wiki/Subject_Alternative_Name
[uaa]: https://github.com/cloudfoundry/uaa
[uaa-releases]: https://github.com/cloudfoundry/uaa-release/releases
