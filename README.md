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
export RBAC_API_ID=--your Auth0 API Identifier--
export RBAC_DOMAIN=--your Auth0 domain--
```

Build and run
```
go run .
```