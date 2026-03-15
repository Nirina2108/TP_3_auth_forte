## TP2 - Authentification fragile

Objectif du TP2 :

1. Ameliorer la securite du projet TP1.
2. Ne plus stocker le mot de passe en clair dans la base.
3. Utiliser un hash BCrypt pour enregistrer les mots de passe.
4. Ajouter une politique de mot de passe stricte :
    - 12 caracteres minimum
    - 1 majuscule
    - 1 minuscule
    - 1 chiffre
    - 1 caractere special
5. Ajouter une protection anti brute force :
    - 5 tentatives echouees maximum
    - blocage temporaire pendant 2 minutes
6. Ajouter des tests unitaires et de validation.
7. Connecter le projet a SonarCloud.
8. Garder en tete que le TP2 reste fragile, car le secret circule encore pendant le login.

## TP2 - Authentification fragile

Objectif du TP2 :

1. Ameliorer la securite du projet TP1.
2. Ne plus stocker le mot de passe en clair dans la base.
3. Utiliser un hash BCrypt pour enregistrer les mots de passe.
4. Ajouter une politique de mot de passe stricte :
   - 12 caracteres minimum
   - 1 majuscule
   - 1 minuscule
   - 1 chiffre
   - 1 caractere special
5. Ajouter une protection anti brute force :
   - 5 tentatives echouees maximum
   - blocage temporaire pendant 2 minutes
6. Ajouter des tests unitaires.
7. Connecter le projet a SonarCloud.
8. Expliquer que le TP2 reste fragile meme si la base est plus securisee.