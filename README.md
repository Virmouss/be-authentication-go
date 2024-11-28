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
<<<<<<< HEAD
/profile/edit (requires Bearer token, "id", "username", optional "current_password", "password", "repassword")

**Admin roles:**\
/profile/reset-password (requires Bearer token, "id", "username")\
/admin/users (requires Bearer token)
=======
/profile/edit (requires Bearer token, "id", "username", "password", "repassword")

**Admin roles:**\
/profile/reset-password (requires Bearer token, "id", "username")\
/admin/users (requires Bearer token)
>>>>>>> da1f06ee4fcb9a1f4dd2152a1b8440583d674243
