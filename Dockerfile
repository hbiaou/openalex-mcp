# Use an official Node.js runtime as a parent image (using Node.js 18.17.1-alpine3.16 for enhanced security)
FROM node:18.17.1-alpine3.16

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json (if available) to the working directory
COPY package*.json ./

# Install only production dependencies
RUN npm install --production

# Copy the rest of the application code to the container
COPY . .

# Expose the port defined in the .env (default is 3000)
EXPOSE 3000

# Define environment variable for production
ENV NODE_ENV=production

# Start the MCP server
CMD ["node", "src/server.js"]