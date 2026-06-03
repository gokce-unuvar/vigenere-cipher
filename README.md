# Chiffrement et cryptanalyse de Vigenère

## Description

Ce projet implémente l’algorithme de chiffrement de Vigenère ainsi que plusieurs méthodes de cryptanalyse permettant de retrouver la clé et le message original à partir d’un texte chiffré.

Il s’inscrit dans un cadre pédagogique visant à comprendre les principes de la cryptographie classique et les faiblesses des chiffrements polyalphabétiques.


## Fonctionnalités

* Chiffrement et déchiffrement de Vigenère
* Analyse de texte chiffré
* Calcul d’indices de coïncidence (IC)
* Analyse des décalages
* Cryptanalyse progressive (plusieurs versions)


## Structure du projet

* `test-*.py` : scripts de test et d’expérimentation
* `data/` :

  * fichiers `.cipher` : textes chiffrés
  * fichiers `.plain` : textes en clair
  * fichiers `.key` : clés associées
* `test-all.sh` : script pour exécuter l’ensemble des tests

## Utilisation

### 1. Cloner le projet

```bash
git clone https://github.com/dalisadi/vigenere-cipher.git
cd vigenere-cipher
```

### 2. Lancer les tests

Exécuter un script spécifique :

```bash
python test-4-decalages.py
```

Ou lancer tous les tests :

```bash
bash test-all.sh
```

## Contenu technique

Le projet couvre plusieurs aspects de la cryptanalyse :

* Calcul de l’indice de coïncidence pour estimer la longueur de la clé
* Analyse des fréquences de lettres
* Détection des décalages (type César)
* Reconstruction progressive de la clé
* Déchiffrement automatique du texte

## Concepts abordés

* Cryptographie classique
* Chiffrement symétrique
* Algorithme de Vigenère
* Analyse fréquentielle
* Cryptanalyse

## Limites de sécurité

Le chiffrement de Vigenère est vulnérable aux techniques de cryptanalyse :

* Analyse fréquentielle
* Détection de la longueur de clé
* Attaques statistiques

Ce projet est donc à but pédagogique.

## Objectifs du projet

* Implémenter un algorithme de chiffrement
* Comprendre les faiblesses des systèmes classiques
* Appliquer des méthodes de cryptanalyse
* Manipuler des données textuelles et statistiques

## Auteur

Gökçe Şükriye ÜNÜVAR
Etudiante en informatique
