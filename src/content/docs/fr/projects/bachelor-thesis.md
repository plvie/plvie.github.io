---
title: "Mémoire de Licence : Calcul de la Fonction de Mertens"
lastUpdated: 2024-06-01T00:00:00.000Z
draft: false
tags:
  - Théorie des Nombres
  - Recherche
author: "Paul Vié"
---


Ce projet de recherche est consacré au calcul de la **fonction de Mertens**.

Il s'agit de mon mémoire de licence à l'Université Paris Cité, sous la supervision de [Cathy Swaenepoel](https://webusers.imj-prg.fr/~cathy.swaenepoel/).

La fonction de Mertens est définie comme \\(M(x) = \sum_{n=1}^{x} \mu(n)\\), où \\(\mu(n)\\) est la fonction de Möbius.

Dans ce projet, j'explore une méthode de calcul et les aspects théoriques liés à la fonction de Mertens et à ce calcul, en mettant l'accent sur l'optimisation et l'efficacité, car le code n'était pas écrit clairement dans le papier original.

Tous les détails du projet sont fournis dans le rapport, et vous pouvez trouver le code source complet ainsi que les diapositives de présentation dans ce répertoire [mertens](https://github.com/plvie/school_project/tree/main/mertens).

C'était un sujet très intéressant qui m'a permis de mélanger 2 de mes passions : la théorie des nombres et l'optimisation de code en C.

## Rapport

Lisez le rapport complet du projet ici :
[report_mertens.pdf](https://github.com/plvie/school_project/blob/main/mertens/report_mertens.pdf)

## Diapositives de Présentation

Pour un aperçu visuel du projet, consultez les diapositives :
[Slides](https://github.com/plvie/school_project/blob/main/mertens/slides.pdf)

## Code Source

Le code source est écrit en C et optimisé pour les performances. Vous pouvez trouver l'implémentation principale ici :
[Fichier de calcul principal](https://github.com/plvie/school_project/blob/main/mertens/mertens_compute.c)

N'hésitez pas à explorer le code et à me contacter si vous avez des questions sur l'implémentation ou l'approche mathématique (même si le code est un peu ancien maintenant !).