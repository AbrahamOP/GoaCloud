/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./assets/templates/**/*.html",
    "./templates/**/*.html",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Outfit', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
