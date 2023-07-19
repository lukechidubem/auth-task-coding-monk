import mongoose from 'mongoose';
import http from 'http';
import dotenv from 'dotenv';

dotenv.config();

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

import app from './app';

const server = http.createServer(app);

const DATABASE = process.env.DATABASE || '';
const PASSWORD = process.env.DATABASE_PASSWORD || '';

const DB = DATABASE.replace('<PASSWORD>', PASSWORD);

mongoose
  .connect(DB, {
    retryWrites: true,
    w: 'majority',
  })
  .then(() => console.log('DB connection successful!'));

const port = process.env.PORT || 4000;

server.listen(port, () => {
  console.log(`App running on port ${port}...`);
});

process.on('unhandledRejection', (err: Error) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
