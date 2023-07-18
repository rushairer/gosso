# gosso

An SSO site written in Go.

## Development

1.

```shell
go install github.com/cosmtrek/air@latest
```

2.

```shell
air -d -c .air/web
```

## More

```shell
# Generate a private key and self-signed certificate for dev.apigg.net(127.0.0.1)
openssl req -x509 -out dev.apigg.net.crt \
    -keyout dev.apigg.net.key \
    -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=dev.apigg.net' -extensions EXT -config <( \
     printf "[dn]\nCN=dev.apigg.net\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:dev.apigg.net\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

# migrate db
migrate create -ext sql -dir migrations -seq create_users_table
migrate -database mysql://$MYSQL_DSN -path migrations up

```
