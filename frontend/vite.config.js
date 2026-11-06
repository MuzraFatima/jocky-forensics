import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendTarget = env.VITE_API_BASE_URL || env.VITE_API_URL || 'http://127.0.0.1:8000';

  return {
    plugins: [react()],
    build: {
      rollupOptions: {
        output: {
          // React and the router change far less often than app code, so they get
          // their own long-cached chunk instead of being re-downloaded on every release.
          manualChunks: {
            vendor: ['react', 'react-dom', 'react-router-dom'],
          },
        },
      },
    },
    server: {
      port: 5173,
      host: true,
      proxy: {
        '/api': {
          target: backendTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
