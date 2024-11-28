# Run the app
```bash
go mod tidy
go run main.go
```
# Environment configuration example
create .env file :

```bash
DB_HOST=localhost
DB_NAME=database
DB_PORT=8080
DB_USER=user
DB_PASS=admin

API_KEY=secret-key

GRPC_ADDRESS=localhost:8080
GRPC_PORT=8000

GIN_HOST=localhost
GIN_PORT=800
```

# Endpoints
/signup (requires "username", "password", "repassword")\
/login  (requires "username", "password")\
/logout (requires Bearer token)\
/profile (requires Bearer token, "id")\
/profile/edit (requires Bearer token, "id", "username", "password", "repassword")