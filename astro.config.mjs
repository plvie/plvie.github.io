// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';

// https://astro.build/config
export default defineConfig({
	site: 'https://plvie.github.io',
	markdown: {
		remarkPlugins: [remarkMath],
		rehypePlugins: [rehypeKatex],
	},
	integrations: [
		starlight({
			title: 'Garab',
			description: 'Engineering Student | Cryptography Enthusiast',
			defaultLocale: 'fr',
			locales: {
				fr: {
					label: 'Français',
					lang: 'fr',
				},
				en: {
					label: 'English',
					lang: 'en',
				},
			},
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/plvie' },
				{ icon: 'discord', label: 'Discord', href: 'https://discord.com/users/1088560800509214820' },
			],
			sidebar: [
				{
					label: 'Writeups',
					translations: {
						en: 'Writeups',
						fr: 'Writeups',
					},
					collapsed: true,
					autogenerate: { directory: 'writeups' },
				},
				{
					label: 'Courses',
					translations: {
						en: 'Courses',
						fr: 'Cours',
					},
					collapsed: true,
					autogenerate: { directory: 'courses' },
				},
				{
					label: 'About',
					translations: {
						en: 'About',
						fr: 'À propos',
					},
					collapsed: true,
					autogenerate: { directory: 'about' },
				},
			],
			customCss: [
				'./src/styles/custom.css',
			],
		}),
	],
});
