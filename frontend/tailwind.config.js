/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          DEFAULT: '#0B1220',
          dark: '#070C16',
          light: '#131E33',
        },
        cyan: {
          DEFAULT: '#00C2FF',
          hover: '#00A8DE',
        },
        cyber: {
          bg: '#F8FAFC',
          card: '#FFFFFF',
          border: '#E2E8F0',
          borderLight: '#CBD5E1',
          primary: '#0B1220',
          secondary: '#475569',
          muted: '#94A3B8',
          accent: '#00C2FF',
          success: '#10B981',
          warning: '#F59E0B',
          danger: '#EF4444',
        }
      },
      fontFamily: {
        sans: ['Inter', 'Poppins', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
