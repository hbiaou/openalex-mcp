# OpenAlex MCP Server

Node.js MCP server using Express and Axios to proxy queries to the OpenAlex API.

**Author:** Samadori H. Biaou <hbiaou@gmail.com>

**License:** MIT License

[![Certified by MCP Review](https://img.shields.io/badge/MCP%20Review-Certified-blue)](https://mcpreview.com/mcp-servers/hbiaou/openalex-mcp)

## Prerequisites
- Node.js (>=14)
- npm

## Installation
```sh
npm install
```

## Configuration
Create a `.env` file in the project root with the following content:
```
PORT=3000
OPENALEX_BASE_URL=https://api.openalex.org
MAILTO=your-email@example.com
NEW_RELIC_LICENSE_KEY=your_new_relic_license_key_here
```

## Running the Server
```sh
npm start
```
The server listens on http://localhost:\<PORT\>

## API
### GET /search
Query parameter:
- `q`: search term

Example:
```sh
GET http://localhost:3000/search?q=machine%20learning
```

## Production Deployment

### Docker
A Dockerfile is provided for production deployment.
- **Build the Docker image:**
  ```sh
  docker build -t openalex-mcp .
  ```
- **Run the container:**
  ```sh
  docker run -p 3000:3000 -d openalex-mcp
  ```

### Environment Configuration
Ensure that production environment variables (e.g., PORT and OPENALEX_BASE_URL) are correctly set. For sensitive data, consider using a secrets manager.

### Scaling and Monitoring
- **Scaling:** Use container orchestrators like Docker Swarm or Kubernetes to scale horizontally based on load.
- **Monitoring:** Integrate monitoring solutions (e.g., New Relic, Prometheus, or Grafana) to track server health and performance.

### Backup Procedures
Implement automated backup solutions for critical data and configuration files. Regularly back up container volumes and databases if applicable.

## Testing and CI/CD
A CI pipeline is configured using GitHub Actions to run unit and integration tests on every push and pull request.