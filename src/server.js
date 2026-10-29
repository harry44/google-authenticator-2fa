import { app } from './app.js';

const port = Number(process.env.PORT || 3000);
const server = app.listen(port, () => {
  console.log(`Google Authenticator 2FA demo listening on http://localhost:${port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
