import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    build: {
        rollupOptions: {
            output: {
                manualChunks: {
                    'vendor-react': ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query'],
                    'vendor-graph': ['react-force-graph-2d'],
                    'vendor-map': ['maplibre-gl', 'react-map-gl'],
                    'vendor-charts': ['recharts'],
                },
            },
        },
    },
    server: {
        proxy: {
            '/api': {
                target: 'http://localhost:8000',
                changeOrigin: true,
                ws: true,
            },
        },
    },
});
