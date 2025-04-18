const request = require('supertest');
const nock = require('nock');
require('dotenv').config();
const app = require('../src/server');

describe('GET /search', () => {
  // Intercept calls to the OpenAlex API with nock
  before(() => {
    nock(process.env.OPENALEX_BASE_URL)
      .get(/\/works/)
      .query(true)
      .reply(200, {
        meta: { count: 1 },
        results: [{ id: 'test', title: 'Test Title' }]
      });
  });

  after(() => {
    nock.cleanAll();
  });

  it('should return JSON with meta and results properties when a query is provided', (done) => {
    request(app)
      .get('/search?q=machine%20learning')
      .expect(200)
      .expect('Content-Type', /json/)
      .expect((res) => {
        if (!('meta' in res.body)) throw new Error('Missing meta property');
        if (!('results' in res.body)) throw new Error('Missing results property');
      })
      .end(done);
  });

  it('should return 400 if the query parameter "q" is missing', (done) => {
    request(app)
      .get('/search')
      .expect(400)
      .end(done);
  });
});