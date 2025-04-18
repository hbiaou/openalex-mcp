require('newrelic');
require('dotenv').config();
const express = require('express');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;
const openAlexBaseUrl = process.env.OPENALEX_BASE_URL;

// Middleware for JSON parsing
app.use(express.json());

// GET endpoint for searching OpenAlex works by title
app.get('/search', async (req, res) => {
  const query = req.query.q;

  if (!query) {
    return res.status(400).json({ error: 'Query parameter "q" is required.' });
  }

  if (!openAlexBaseUrl) {
    console.error('OPENALEX_BASE_URL is not defined in the environment variables.');
    return res.status(500).json({ error: 'Server configuration error.' });
  }

  const searchUrl = `${openAlexBaseUrl}/works?filter=title.search:${encodeURIComponent(query)}`;

  try {
    console.log(`Forwarding search request to: ${searchUrl}`);
    const response = await axios.get(searchUrl);
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching data from OpenAlex API:', error.message);
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error('OpenAlex API Response Status:', error.response.status);
      console.error('OpenAlex API Response Data:', error.response.data);
      res.status(error.response.status).json({
        error: 'Failed to fetch data from OpenAlex API.',
        details: error.response.data
      });
    } else if (error.request) {
      // The request was made but no response was received
      console.error('No response received from OpenAlex API:', error.request);
      res.status(503).json({ error: 'No response received from OpenAlex API.' });
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error('Error setting up request to OpenAlex API:', error.message);
      res.status(500).json({ error: 'Internal server error while contacting OpenAlex API.' });
    }
  }
});

if (require.main === module) {
 app.listen(port, () => {
   console.log(`MCP server listening at http://localhost:${port}`);
 });
} else {
 module.exports = app;
}