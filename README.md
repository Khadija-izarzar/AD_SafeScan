# AD-SafeScan

AD-SafeScan est un outil graphique d’audit de sécurité pour les environnements Windows, permettant de réaliser rapidement plusieurs contrôles essentiels sur une machine locale ou membre d’un domaine Active Directory.

## Fonctionnalités

- **Authentification sécurisée** : Accès protégé par mot de passe à l’application.
- **Vérification des droits administrateur** : Avertissement si l’application n’est pas lancée en mode administrateur.
- **Audit des comptes AD** : Liste les comptes utilisateurs du domaine ou locaux.
- **Audit des ports ouverts** : Affiche les ports réseau actuellement à l’écoute.
- **Audit des services** : Liste les services Windows actifs.
- **Audit des comptes locaux** : Affiche tous les comptes utilisateurs locaux.
- **Audit de l’activité USB** : Détecte les périphériques USB connectés.
- **Audit des logs de sécurité** : Récupère les derniers événements de sécurité Windows (mode administrateur recommandé).
- **Sauvegarde des résultats** : Permet d’exporter les résultats d’audit sur le bureau.
- **Interface moderne** : Application Tkinter avec logo, icône, et design personnalisé.

## Prérequis

- **Système d’exploitation** : Windows 10 ou supérieur.
- **Python** : 3.8 ou supérieur (pour exécution du script `.py`).
- **Dépendances Python** :
  - `tkinter` (inclus avec Python standard sous Windows)
  - `Pillow` (`pip install pillow`)
  - `psutil` (`pip install psutil`)
- **Fichiers ressources** :
  - `icone.ico` et `logo.png` doivent être placés dans `Documents/AD-Scanner` de l’utilisateur courant.

## Installation

### 1. Utilisation du binaire

- Téléchargez `AD-Scanner-v2.exe` (ou le binaire généré par PyInstaller).
- Placez les fichiers `icone.ico` et `logo.png` dans le dossier `Documents/AD-Scanner`.
- Double-cliquez sur l’exécutable pour lancer l’application.

### 2. Utilisation du script Python

- Clonez ou copiez le fichier `AD-Scanner-v2.py`.
- Installez les dépendances :
  ```bash
  pip install pillow psutil
  ```
- Placez `icone.ico` et `logo.png` dans `Documents/AD-Scanner`.
- Lancez le script :
  ```bash
  python AD-Scanner-v2.py
  ```

## Architecture du projet

```
AD-Scanner/
│
├── AD-Scanner-v2.exe        # Version exécutable
└── Documents/
    └── AD-Scanner/
        ├── icone.ico        # Icône de l’application
        └── logo.png         # Logo affiché dans l’interface
```

## Fonctionnement

1. **Lancement** : L’application démarre par une fenêtre d’authentification (mot de passe requis).
2. **Interface principale** : Une fois authentifié, l’interface propose plusieurs modules d’audit accessibles par boutons.
3. **Exécution des audits** : Chaque module lance un contrôle spécifique et affiche les résultats dans la zone centrale.
4. **Sauvegarde** : Les résultats peuvent être exportés sur le bureau de l’utilisateur.
5. **Mode administrateur** :  
   - Pour accéder aux logs de sécurité Windows, il est **fortement recommandé** de lancer l’application en tant qu’administrateur (clic droit > Exécuter en tant qu’administrateur).
   - Certains audits nécessitent des droits élevés pour fonctionner correctement.

## Conseils d’utilisation

- **Mot de passe par défaut** : `ADSafe@2025` (modifiable dans le code source).
- **Sécurité** : Ne partagez pas le mot de passe ou l’exécutable sans précaution.
- **Logs de sécurité** : Si l’audit des logs échoue, relancez l’application en mode administrateur.
