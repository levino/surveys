/** @type {import('tailwindcss').Config} */
module.exports = {
	content: ["./ui/**/*.templ", "./*.go"],
	theme: { extend: {} },
	plugins: [require("daisyui")],
	daisyui: {
		logs: false,
		themes: [
			{
				surveys: {
					primary: "#2563eb",
					"primary-content": "#ffffff",
					secondary: "#64748b",
					accent: "#16a34a",
					neutral: "#1f2937",
					"base-100": "#ffffff",
					"base-200": "#f6f7f9",
					"base-300": "#e5e7eb",
					info: "#0ea5e9",
					success: "#16a34a",
					warning: "#f59e0b",
					error: "#dc2626",
				},
			},
			"light",
			"dark",
		],
	},
};
