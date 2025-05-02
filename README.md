# jwtHelper

`jwtHelper` is a lightweight Go package that simplifies JWT creation and validation in HTTP applications. It supports HMAC-based signing (HS512), role-based access control, and integrates with custom error encoding via [`errorhelper`](https://github.com/gigatar/error-helper).

## Features

* Create JWT tokens with custom claims
* Middleware to validate JWT and enforce role-based permissions
* Integration-ready with any `http.Handler`
* Built-in support for common error responses via `errorhelper`

## Installation

```bash
go get github.com/gigatar/jwtHelper
```

## Environment Variables

The package expects two environment variables:

* `JWT_PASSWORD`: Secret used to sign the JWT
* `JWT_TTL`: Token time-to-live in minutes (defaults to 5 minutes if unset or invalid)

## Usage

### Create a Token

```go
import "github.com/gigatar/jwtHelper"

token, err := jwtHelper.CreateJWT("user@example.com", "1234", "my-service", []string{"admin"})
if err != nil {
	log.Fatal(err)
}
fmt.Println("JWT:", token)
```

### Validate JWT Middleware

```go
import (
	"net/http"
	"github.com/gigatar/jwtHelper"
	"github.com/gigatar/error-helper"
)

mux := http.NewServeMux()
mux.Handle("/secure", jwtHelper.ValidateJWT(
	[]string{"admin"},
	errorhelper.NewDefaultEncoder(nil),
)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Access granted!"))
})))

http.ListenAndServe(":8080", mux)
```

### Request Headers Available in Handlers

After JWT is validated, the following headers are added to the request:

* `email`: User's email
* `user-id`: User ID
* `roles`: Colon-separated list of roles

## Custom Error Handling

You can inject any implementation of the `errorhelper.Encoder` interface to customise how errors are rendered.

## License

MIT
