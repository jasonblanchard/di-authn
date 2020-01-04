require('dotenv').config();
const fetch = require('node-fetch');
const cookieParser = require('cookie');
const jwt = require('jsonwebtoken');

const baseUrl = process.env.SERVICE_BASE_URL;

test('the service is running', () => {
  return fetch(`${baseUrl}/health`)
    .then(response => response.json())
    .then(body => {
      expect(body.health).toEqual("ok");
    });
});

describe('GET /login', () => {
  it('returns 401 when given invalid username', () => {
    return fetch(`${baseUrl}/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'test', password: 'wrong' }),
      headers: { 'Content-Type': 'application/json' },
    })
      .then(response => {
        expect(response.status).toEqual(401);
      });
  });

  it('returns 201 when given valid username', () => {
    return fetch(`${baseUrl}/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'test', password: process.env.TEST_PASSWORD }),
      headers: { 'Content-Type': 'application/json' },
    })
      .then(response => {
        const cookies = response.headers.get('set-cookie');
        expect(response.status).toEqual(201);
        expect(cookies).toMatch(/^sessionId=.+/);
      });
  });
});

describe('GET /csrf', () => {
  it('returns a CSRF token', () => {
    return fetch(`${baseUrl}/csrf`)
      .then(response => response.json())
      .then(body => {
        expect(body.csrfToken).toMatch(/\w+/);
      });
  });
});

describe('GET /session/authn', () => {
  it('returns 401 without an active session', () => {
    return fetch(`${baseUrl}/session/authn`)
      .then(response => {
        expect(response.redirected).toEqual(true);
        expect(response.url).toMatch(/\/health/);
      });
  });

  it('returns 401 with json when client accepts json', () => {
    return fetch(`${baseUrl}/session/authn`, {
      headers: {
        "Accept": "application/json"
      }
    })
      .then(response => {
        expect(response.status).toEqual(401);
        return response.json();
      }).then(body => {
        expect(body).toEqual({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Unauthorized'
        });
      });
  });

  it('returns 200 with token with valid session', () => {
    return fetch(`${baseUrl}/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'test', password: process.env.TEST_PASSWORD }),
      headers: { 'Content-Type': 'application/json' },
    })
      .then(response => {
        const cookieString = response.headers.get('set-cookie');
        const cookies = cookieParser.parse(cookieString);
        return fetch(`${baseUrl}/session/authn`, {
          headers: {
            cookie: `sessionId=${cookies.sessionId}`
          }
        });
      })
      .then(response => {
        expect(response.status).toEqual(200);
        const authorizationHeader = response.headers.get('Authorization');
        expect(authorizationHeader).toMatch(/^Bearer .+/);
        const token = authorizationHeader.match(/^Bearer (.+)/)[1];
        const payload = jwt.decode(token);

        expect(payload.uesrUuid).toMatch(/\w+/);
        expect(payload.csrfToken).toMatch(/\w+/);
      });
  });

  it('rejects POST requests without a CSRF token', async () => {
    const loginResponse = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'test', password: process.env.TEST_PASSWORD }),
      headers: { 'Content-Type': 'application/json' },
    });

    const cookieString = loginResponse.headers.get('set-cookie');
    const cookies = cookieParser.parse(cookieString);

    const authnResponse = await fetch(`${baseUrl}/session/authn`, {
      method: 'POST',
      headers: {
        cookie: `sessionId=${cookies.sessionId}`,
      },
    });

    expect(authnResponse.status).toEqual(403);
  });

  it('allows POST requests with CSRF token', async () => {
    const loginResponse = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'test', password: process.env.TEST_PASSWORD }),
      headers: { 'Content-Type': 'application/json' },
    });

    const cookieString = loginResponse.headers.get('set-cookie');
    const cookies = cookieParser.parse(cookieString);

    const csrfResponse = await (fetch(`${baseUrl}/csrf`));
    const csrfResponseCookiesString = csrfResponse.headers.get('set-cookie');
    const csrfResponseCookies = cookieParser.parse(csrfResponseCookiesString);
    const { csrfToken } = await csrfResponse.json();

    const authnResponse = await fetch(`${baseUrl}/session/authn`, {
      method: 'POST',
      headers: {
        cookie: `sessionId=${cookies.sessionId}; _csrf=${csrfResponseCookies['_csrf']}`,
        'CSRF-Token': csrfToken,
      },
    });

    expect(authnResponse.status).toEqual(200);
  });
});

describe('DELETE /session', () => {
  it('removes the cookie', () => {
    return fetch(`${baseUrl}/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'test', password: process.env.TEST_PASSWORD }),
      headers: { 'Content-Type': 'application/json' },
    })
      .then(response => {
        const cookieString = response.headers.get('set-cookie');
        const cookies = cookieParser.parse(cookieString);
        return fetch(`${baseUrl}/session/authn`, {
          headers: {
            cookie: `sessionId=${cookies.sessionId}`
          }
        });
      })
      .then(() => {
        return fetch(`${baseUrl}/session`, {
          method: 'DELETE'
        });
      })
      .then(response => {
        expect(response.status).toEqual(204);
        const cookieString = response.headers.get('set-cookie');
        const cookies = cookieParser.parse(cookieString);
        expect(cookies.sessionId).toEqual('');
      });
  });
});
