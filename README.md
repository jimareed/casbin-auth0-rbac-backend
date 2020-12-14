# casbin-auth0-rbac-backend
Example RBAC implementation with Casbin and Auth0

## Setup

### Build & Run

Grab the dependencies
```
go get
```

Set environment variables
```
export DATA_API_ID=--your Auth0 API Identifier--
export DATA_DOMAIN=--your Auth0 domain--
```

Build and run
```
go run .
```

### Sources
- https://auth0.com/blog/authentication-in-golang/
- https://auth0.com/docs/quickstart/backend/golang/01-authorization
- https://auth0.com/docs/users/user-search/retrieve-users-with-get-users-by-id-endpoint
