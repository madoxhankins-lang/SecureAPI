# Secure API

I built this with Express and TypeScript. It uses JWTs for login and bcrypt to hash passwords. Regular users can log in, but only admins can access `/secure`.

## Run it

Use Node.js 22 or 24:

```sh
cd code/start
npm ci
npm run setup
npm run dev
```

The API runs at `http://localhost:3000`. Setup creates a private `.env` with the admin credentials. Accounts are stored in memory and reset on restart.

## Routes

- `POST /auth/register` — create a regular user with `email` and `password`.
- `POST /auth/login` — get a 15-minute token.
- `GET /me` — view your profile.
- `GET /secure` — admin access only.
- `GET /health` — check the server.

Send tokens as `Authorization: Bearer YOUR_TOKEN`.

I added validation, rate limits, security headers, CORS, request logs, and error handling. Run `npm test` for the tests or `npm run demo` while the server is running. For production scripts, use `npm run build` then `npm start`.

For the screen-share demo, open `bruno/Secure API` in the VS Code Bruno extension and send requests 01–10 in order. Select the **Local** environment first. Registration saves a fresh email and login saves tokens, so individual requests work too. `npm run setup` creates the private demo environment. Local setup allows 100 failed auth attempts per 15 minutes; the server default is 10. Successful auth requests do not count.
