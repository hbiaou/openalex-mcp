# OpenAlex MCP Server Development Guide

## Prerequisites
- Node.js (v18+ recommended)
- npm or yarn
- GitHub account
- Visual Studio Code (recommended)
- Basic TypeScript knowledge

## Step 1: Project Setup
```bash
# Create project directory
mkdir openalex-mcp-server
cd openalex-mcp-server

# Initialize npm project
npm init -y

# Install core dependencies
npm install @modelcontextprotocol/sdk axios typescript ts-node @types/node

# Install development dependencies
npm install -D ts-node-dev @types/node
```

## Step 2: TypeScript Configuration
Create `tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "strict": true,
    "esModuleInterop": true,
    "outDir": "./build",
    "rootDir": "./src"
  },
  "include": ["src/**/*"]
}
```

## Step 3: Project Structure
```bash
mkdir -p src/tools src/resources
touch src/index.ts
touch src/openalex-service.ts
```

## Step 4: OpenAlex Service Implementation
Create `src/openalex-service.ts`:
```typescript
import axios from 'axios';

export class OpenAlexService {
  private baseUrl = 'https://api.openalex.org';

  async searchWorks(query: string) {
    try {
      const response = await axios.get(`${this.baseUrl}/works`, { 
        params: { search: query, per_page: 10 } 
      });
      return response.data.results;
    } catch (error) {
      console.error('OpenAlex API Error:', error);
      throw error;
    }
  }

  async getWorkDetails(id: string) {
    try {
      const response = await axios.get(`${this.baseUrl}/works/${id}`);
      return response.data;
    } catch (error) {
      console.error('OpenAlex API Error:', error);
      throw error;
    }
  }
}
```

## Step 5: MCP Server Implementation
Create `src/index.ts`:
```typescript
import { MCPServer } from '@modelcontextprotocol/sdk/server';
import { OpenAlexService } from './openalex-service';

const server = new MCPServer({
  name: 'OpenAlex Research Server',
  version: '1.0.0'
});

const openAlexService = new OpenAlexService();

// Tool: Search Academic Works
server.addTool({
  name: 'search-academic-works',
  description: 'Search academic publications through OpenAlex',
  async handler(query: string) {
    return await openAlexService.searchWorks(query);
  }
});

// Tool: Get Work Details
server.addTool({
  name: 'get-work-details',
  description: 'Retrieve detailed information about a specific academic work',
  async handler(id: string) {
    return await openAlexService.getWorkDetails(id);
  }
});

server.start();
```

## Step 6: Package Scripts
Update `package.json`:
```json
{
  "scripts": {
    "start": "ts-node src/index.ts",
    "build": "tsc",
    "dev": "ts-node-dev --respawn src/index.ts"
  }
}
```

## Step 7: Git Initialization
```bash
# Initialize git repository
git init
touch .gitignore

# Create .gitignore content
echo "node_modules/
build/
.env
*.log" > .gitignore

# Initial commit
git add .
git commit -m "Initial OpenAlex MCP Server setup"
```

## Step 8: GitHub Repository
```bash
# Create GitHub repository (replace USERNAME)
gh repo create openalex-mcp-server --public
git branch -M main
git remote add origin https://github.com/USERNAME/openalex-mcp-server.git
git push -u origin main
```

## Running the Server
```bash
# Development mode
npm run dev

# Build for production
npm run build
npm start
```

## Additional Considerations
- Implement error handling
- Add rate limiting
- Create more sophisticated search tools
- Consider caching responses

## Troubleshooting
- Ensure API keys if required
- Check network connectivity
- Verify TypeScript and Node.js versions

## Future Enhancements
- Add more granular OpenAlex API interactions
- Implement advanced filtering
- Create more complex research tools

## Deployment Options
1. Local hosting
2. Cloud platforms (AWS, Azure, Heroku)
3. Docker containerization
