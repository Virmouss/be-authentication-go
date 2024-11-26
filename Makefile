gen:
	@protoc \
	--proto_path=app/proto \
	--go_out=app/generated/auth --go_opt=paths=source_relative \
	--go-grpc_out=app/generated/auth --go-grpc_opt=paths=source_relative \
	app/proto/Users.proto
