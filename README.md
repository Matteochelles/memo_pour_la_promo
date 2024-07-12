# memo git et Github
#Diff entre Git et Github
git = projet open source de gestion de version de code
github = plateforme d'hebergement de code

# workflow git et github de base : 
processus etape par etape:
1.- faire une modif en local (ex: sur vscode)
2.- git add . (le '.' est pour add tout le repertoire)
3.- git commit -m "message du commit" (mettre un message decrivant la modif)
4.- git push origin main (pousse les modif faites en local vers github)

ajouter une clé a son github :
https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account

lien pour generer sa clé privé et sa clé publique:
https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent

# Travail collaboratif : 

1. recevoir l'invite de l'admin du code
2. une fois invité on va sur le code en question a droite il faut cliquer sur le bouton code en vert et copier coller le lien (SSH pas hhtp c'est important) ecrire "git clone" suivi du lien a coller dans le terminal(attention a bien choisir un repertoire ne contenant pas de .git) 
3. on a donc cloner le dossier contenant les fichiers du code de l'admin.
4. on peut l'ouvrir sous vscode par exemple (ATTENTION BIEN OUVRIR AVEC OPEN FOLDER EXACTEMENT LE   BON DOSSIER)
5. on peut desormais faire des modifs crer d'autres fichiers ..etc

# Upload de son travail collaboratif et diverses commandes liées a ca :

commandes = "git pull" sur le terminal (TOUJOURS VERIFIER QU'ON SOIT DANS LE BON DOSSIER) permet de mettre a jour son fichier si quelqun l'as modifé

IMPORTANT EN CAS DE CONFLITS (c'est a dire qu'on envoi une modifications alors que quelqun d'autre a deja envoyer une modifications que nous n'avons pas recu via git pull): 

git config pull.rebase false 
PUIS git pull:
une fenetre apparait indiquant que le terminal a compris il demande juste qu'on specifie un msg texte (une note en gros) une fois la note ecrite faites : ctrl + s puis ctrl + x (la fenetre se ferme)
-FINALEMENT  on peut faire la commande git push et envoyer son commit

# ENVOYER SON TRAVAIL SI IL N'YA PAS DE CONFLITS:
simplement faire les modif puis appliquer les 3 étapes : 
git add (nom du fichier si vous en avez crée un, sinon mettre un .)
git commit -m"le message"
git push (on envoi le file)

# LE CAS OU ON TRAVAIL SUR LE MEME CODE, LE MEME FICHIER:
