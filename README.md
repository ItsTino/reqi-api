# Reqi - Webhook Request Inspector & Logger

Debug webhooks and callbacks with ease

## Features

- Request Logging: Capture and inspect HTTP requests in real-time
- API Key Management: Secure access with both public and private endpoints
- High Performance: Optimized for speed with minimal overhead
- Detailed Logging: Capture headers, query parameters, and request bodies
- Secure: JWT authentication for management and API keys for logging

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/reqi.git

# Install dependencies
cd reqi
go mod download

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration

# Run the server
go run cmd/server/main.go
```

### Basic Usage

1. **Register an Account**
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'
```

2. **Create an API Key**
```bash
curl -X POST http://localhost:8080/keys/create \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "My API Key", "is_public": false}'
```

3. **Create a Logger**
```bash
curl -X POST http://localhost:8080/api/logger \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"is_public": false}'
```

4. **Start Capturing Requests**
```bash
# Your logger URL will be provided in the previous response
# Use it to send requests:
curl -X POST "http://localhost:8080/log/your-logger-uuid/any/path" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

5. **View Logs**
```bash
curl -X GET http://localhost:8080/api/logs/your-logger-uuid \
  -H "X-API-Key: your-api-key"
```

## API Documentation

API documentation is available via Swagger UI at `/swagger/index.html` when running the server.

### Key Endpoints

- **Authentication**
  - `POST /auth/register` - Register new user
  - `POST /auth/login` - Login and receive JWT token

- **API Keys**
  - `POST /keys/create` - Create new API key
  - `GET /keys/list` - List all API keys
  - `DELETE /keys/:key` - Revoke API key

- **Loggers**
  - `POST /api/logger` - Create new logger
  - `GET /api/loggers` - List all loggers
  - `GET /api/logs/:uuid` - Show all logs for a logger
  - `GET /api/log/:logger_uuid/:request_uuid` - Get specific log details

- **Logging Endpoint**
  - `ANY /log/:uuid/*path` - Capture any HTTP request

## Configuration

Configuration is managed through environment variables:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=reqi
SERVER_PORT=8080
JWT_SECRET=your-secret-key
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors who have helped shape Reqi
- Built with [Go](https://golang.org/) and [Gin](https://gin-gonic.com/)

---
Built with ❤️ for developers who debug webhooks
