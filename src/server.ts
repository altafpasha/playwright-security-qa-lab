import { app } from './app';

const PORT = process.env.PORT || 3333;

const server = app.listen(PORT, () => {
  console.log(`[SecQA Lab] Server running on http://127.0.0.1:${PORT}`);
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  server.close(() => {
    console.log('[SecQA Lab] Server shut down gracefully on SIGTERM');
  });
});

process.on('SIGINT', () => {
  server.close(() => {
    console.log('[SecQA Lab] Server shut down gracefully on SIGINT');
  });
});
