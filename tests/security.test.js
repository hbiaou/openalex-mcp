const request = require('supertest');
const app = require('../src/server'); // Assumes your Express server is exported from this file
const { expect } = require('chai');

describe('Security Test Suite', function () {
  // SQL/NoSQL Injection Tests
  describe('SQL/NoSQL Injection Tests', function () {
    it('should reject SQL injection in query parameters', async function () {
      const injectionPayload = "'; DROP TABLE users; --";
      const res = await request(app)
        .get(`/users?search=${encodeURIComponent(injectionPayload)}`);
      expect(res.status).to.be.oneOf([400, 422, 500]);
    });

    it('should reject NoSQL injection in JSON body', async function () {
      const injectionPayload = { username: { "$gt": "" } };
      const res = await request(app)
        .post('/login')
        .send(injectionPayload);
      expect(res.status).to.be.oneOf([400, 422, 500]);
    });
  });

  // XSS Payload Validation Tests
  describe('XSS Payload Validation Tests', function () {
    it('should sanitize XSS payloads in user input', async function () {
      const xssPayload = `<script>alert('XSS')</script>`;
      const res = await request(app)
        .post('/comment')
        .send({ comment: xssPayload });
      expect(res.status).to.equal(200);
      expect(res.text).to.not.include(xssPayload);
    });
  });

  // Rate Limit Enforcement Tests
  describe('Rate Limit Enforcement Tests', function () {
    it('should enforce rate limiting for repeated requests', async function () {
      let lastRes;
      for (let i = 0; i < 15; i++) {
        lastRes = await request(app).get('/api/sensitive');
      }
      expect(lastRes.status).to.equal(429);
    });
  });

  // Oversized Payload Rejection Tests
  describe('Oversized Payload Rejection Tests', function () {
    it('should reject payloads that exceed allowed size', async function () {
      const largePayload = 'a'.repeat(10 * 1024 * 1024);
      const res = await request(app)
        .post('/upload')
        .set('Content-Type', 'application/json')
        .send({ data: largePayload });
      expect(res.status).to.be.within(413, 414);
    });
  });

  // Authentication Bypass Attempts
  describe('Authentication Bypass Attempts', function () {
    it('should deny access to protected routes without a token', async function () {
      const res = await request(app).get('/protected');
      expect(res.status).to.equal(401);
    });

    it('should deny access with an invalid or manipulated token', async function () {
      const manipulatedToken = "Bearer invalidtoken";
      const res = await request(app)
        .get('/protected')
        .set('Authorization', manipulatedToken);
      expect(res.status).to.equal(401);
    });
  });

  // Directory Traversal Attempts
  describe('Directory Traversal Attempts', function () {
    it('should reject requests that attempt directory traversal', async function () {
      const res = await request(app).get('/files/../../etc/passwd');
      expect(res.status).to.be.oneOf([400, 403, 404]);
    });
  });

  // CSRF Validation Tests
  describe('CSRF Validation Tests', function () {
    it('should deny requests missing a valid CSRF token', async function () {
      const res = await request(app)
        .post('/change-password')
        .send({ newPassword: 'newpass123' });
      expect(res.status).to.equal(403);
    });
  });
});