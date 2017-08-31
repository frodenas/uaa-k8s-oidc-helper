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
        idp-issuer-url: https://uaa.<system domain>
        client-id: cf
        client-secret: ""
        id-token: <REDACTED>
        refresh-token: <REDACTED>
```

## Installation

Using the standard `go install` (you must have [Go][golang] already installed in your local machine):

```bash
$ go install github.com/frodenas/uaa-k8s-oidc-helper
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

## Contributing

Refer to the [contributing guidelines][contributing].

## License

Apache License 2.0, see [LICENSE][license].

This tool has heavily inspired by the [k8s-oidc-helper][k8s-oidc-helper].

[contributing]: https://github.com/frodenas/stackdriver_exporter/blob/master/CONTRIBUTING.md
[golang]: https://golang.org/
[license]: https://github.com/frodenas/uaa-k8s-oidc-helper/blob/master/LICENSE
[k8s-oidc]: https://kubernetes.io/docs/admin/authentication
[k8s-oidc-helper]: https://github.com/micahhausler/k8s-oidc-helper
[kubeconfig]: https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/
[uaa]: https://github.com/cloudfoundry/uaa
