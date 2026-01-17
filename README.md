# Garab's Portfolio

Site personnel avec writeups CTF et cours de cryptographie.

## Déploiement sur GitHub Pages

### Étape 1: Créer le repository

1. Va sur https://github.com/new
2. Nomme le repository `plvie.github.io`
3. Crée le repository (public)

### Étape 2: Pousser le code

```bash
cd /home/garab/hugo-source/new-site
git remote add origin https://github.com/plvie/plvie.github.io.git
git branch -M main
git commit -m "Initial commit - Astro site"
git push -u origin main
```

### Étape 3: Configurer GitHub Pages

1. Va dans les **Settings** du repository
2. Dans le menu de gauche, clique sur **Pages**
3. Sous **Source**, sélectionne **GitHub Actions**
4. Le site sera automatiquement déployé à chaque push!

### Étape 4: Attendre le déploiement

Le workflow GitHub Actions va:
- Installer Node.js 20
- Installer les dépendances
- Build le site Astro
- Déployer sur GitHub Pages

Ton site sera disponible sur: **https://plvie.github.io**

## Développement local

```bash
# Installer les dépendances
npm install

# Lancer le serveur de dev
npm run dev

# Build pour production
npm run build
```

## Structure

- `/src/content/docs/` - Contenu en anglais
- `/src/content/docs/fr/` - Contenu en français
- `/src/styles/` - Styles CSS personnalisés
- `/public/` - Assets statiques (images, etc.)
