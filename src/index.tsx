import Boom from '@hapi/boom';
import express, { Response, NextFunction } from 'express';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import session from 'express-session';
import csrf from 'csurf';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';

require('dotenv').config();

interface UsersByUsername {
  [key: string]: any;
}

const usersByUsername: UsersByUsername = {
  'test': {
    username: 'test',
    password: process.env.TEST_PASSWORD,
    id: 1,
    uuid: 'bcf4e360-2bd4-41a1-a9d0-786577e02f4a'
  },
  'jason': {
    username: 'jason',
    password: process.env.JASON_PASSWORD,
    id: 2,
    uuid: '2b5545ef-3557-4f52-994d-daf89e04c390'
  }
}

interface UsernamesByApiToken {
  [key: string]: string;
}

const TEST_API_TOKEN = process.env.TEST_API_TOKEN || ''
const JASON_API_TOKEN = process.env.JASON_API_TOKEN || ''

const usernamesByApiToken: UsernamesByApiToken = {
  [TEST_API_TOKEN]: 'test',
  [JASON_API_TOKEN]: 'test',
}

require('dotenv').config();

const PORT = process.env.PORT || 8081;
const JWT_SECRET = process.env.JWT_SECRET || '';
const LOGIN_PATH = process.env.LOGIN_PATH || '';

const app = express();

app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(bodyParser.json());
app.use(session({
  name: 'sessionId',
  secret: process.env.SESSION_SECRET || '',
  resave: false,
  saveUninitialized: true,
  // TODO: Use RedisStore
}));
// const csrfProtection = csrf({ cookie: true });
// TODO: Fix request type
const csrfProtection = (request: any, response: Response, next: NextFunction) => {
  if (request.headers.authorization) {
    return next();
  } else {
    return csrf({ cookie: true })(request, response, next)
  }
}
app.use(cookieParser());

app.get('/health', (_request, response) => {
  return response.json({ health: 'ok' });
});

app.post('/login', (request, response) => {
  const { username, password } = request.body;
  const user = usersByUsername[username];

  if (user && user.password === password) {
    if (request.session) request.session.user = { id: user.id, uuid: user.uuid };
    return response.status(201).end();
  }

  return response.status(401).end();
});

app.get('/csrf', csrfProtection, (request, response) => {
  return response.json({ csrfToken: request.csrfToken() });
});

app.use('/session/authn*', csrfProtection, (request, response) => {
  if (request.headers.authorization) {
    const apiToken = request.headers.authorization.replace("Bearer ", "")
    const username = usernamesByApiToken[apiToken]
    const user = usersByUsername[username]

    if (!user) {
      const error = Boom.unauthorized();
      return response.status(401).send(error.message);
    }

    const token = jwt.sign({
      uesrUuid: user.uuid
    }, JWT_SECRET);
    response.header('Authorization', `Bearer ${token}`);
    return response.status(200).end();
  }
  
  if (request.cookies.sessionId && request?.session?.user) {
    // TODO: Cache this and regenerate when it expires
    var token = jwt.sign({
      uesrUuid: request?.session?.user.uuid,
      csrfToken: request.csrfToken()
    }, JWT_SECRET);
    response.header('Authorization', `Bearer ${token}`);
    return response.status(200).end();
  }

  const error = Boom.unauthorized();

  switch (request.accepts(['html', 'json'])) {
    case 'html':
      return response.redirect(LOGIN_PATH);
    case 'json':
      return response.status(401).json(error.output.payload);
    default:
      return response.status(401).send(error.message);
  }
});

app.delete('/session', (request, response) => {
  request?.session?.destroy(error => {
    response.clearCookie('sessionId');
    response.status(204).end();
  });
});

interface AuthError extends Error {
  code?: string;
}

app.use((err: AuthError, _request: any, response: Response, next: NextFunction) => {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)

  // handle CSRF token errors here
  // console.log(request.headers);
  response.status(403)
  response.json({ error: "Invalid csrf token" });
})

app.listen({ port: PORT }, () => {
  console.log(`🚀 di-auth ready on port ${PORT}`);
});
