import { generate } from 'otplib';

const secret = process.argv[2];
if (!secret) {
  console.error('usage: npm run code -- <base32-secret>');
  process.exit(1);
}

try {
  console.log(await generate({ secret }));
} catch (err) {
  console.error(`Could not generate a code: ${err.message}`);
  process.exit(1);
}
