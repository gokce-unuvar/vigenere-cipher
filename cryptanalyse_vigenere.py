# Sorbonne Université 3I024 2024-2025
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : ÜNÜVAR Gökçe Şükriye 21304812
# Etudiant.e 2 : CIVA Ege 21310970

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier

#Calculer en utilisant frequence.py du TME1 
freq_FR = [0.0811, 0.0081, 0.0338, 0.0428, 0.1471, 0.0106, 0.0086, 0.0073, 
           0.0697, 0.0014, 0.0001, 0.0545, 0.0296, 0.0709, 0.0579, 0.0252, 
           0.0136, 0.0669, 0.0794, 0.0724, 0.0637, 0.0183, 0.0004, 0.0038, 
           0.0030, 0.0013]  
# Chiffrement César
def chiffre_cesar(txt, key):
    """
    Chiffre txt avec une clé "key" de cesar 
    key : un entier entre 0 et 25 inclu
    """

    #verifier que le cle et une lettre de l alphabet
    if key < 0 or key > 25:
        print("cle invalide")
        exit(-1)

    res=""  # on y sauvegarde le texte chiffre

    for c in txt:
        if c.isalpha():
            m = (ord(c.upper()) - ord ('A')+ key) % 26 + ord('A')
            res = res + chr(m)
        else:
            res = res + c

    return res

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    Dechiffre txt avec une clé "key" de cesar 
    key : un entier entre 0 et 25 inclu
    """
    #verifier que le cle et une lettre de l alphabet
    if key < 0 or key > 25:
        print("cle invalide")
        exit(-1)

    res=""   # on y sauvegarde le texte dechiffre

    for c in txt:
        if c.isalpha():
            m = (ord(c.upper()) - ord ('A') -  key) % 26 + ord('A')
            res = res + chr(m)
        else:
            res = res + c

    return res

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    Chiffre txt avec une clé de Vigenère (liste d'entiers)
    """

    res = ""
    
    bloc = len(key)  #recuperer la taille de la cle

    for i in range(len(txt)):
        j = (ord(txt[i].upper()) - ord('A') + key[i % bloc]) % 26 #j la position de la lettre dechiffre dans l alphabet
        res +=chr(j + ord('A'))

    return res

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    Déchiffre txt avec une clé de Vigenère (liste d'entiers)
    """
    res = ""
    
    bloc = len(key)  #recuperer la taille de la cle

    for i in range(len(txt)):
        j = (ord(txt[i].upper()) - ord('A') - key[i % bloc]) % 26 #j la position de la lettre dechiffre dans l alphabet
        res +=chr(j + ord('A'))

    return res

# Analyse de fréquences
def freq(txt):
    """
    Retourne le nombre d’occurrences de chaque lettre de l’alphabet.
    """

    hist=[0]*len(alphabet)
    Occurrences = {}

    for c in txt:
        if c.isalpha():
            if c.upper() not in Occurrences:
                Occurrences[c.upper()] = 1
            else :
                Occurrences[c.upper()] = Occurrences[c.upper()] + 1
    i=0
    for c in alphabet:
        if c in Occurrences:
            hist[i] = Occurrences[c]
        i += 1

    return hist

#freq_FR = freq()

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    Retourne l’indice de la lettre la plus fréquente dans txt
    """

    his = freq(txt)
    max = -1

    for i in range(len(his)):
        if his[i] > max:
            max = his[i]

    return his.index(max)

# indice de coïncidence
def indice_coincidence(hist):
    """
    Calcule l’indice de coïncidence d’un tableau d’occurrences hist
    """

    n=0
    res=0.0
    for i in range(len(hist)):
        res+=hist[i]*(hist[i]-1)
        n+=hist[i]
    if n <= 1:  #si le texte est court ou vide
        return 0.0
    return res/(n*(n-1))

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    Renvoie la longueur probable de la clé en utilisant l'indice de coïncidence.
    """

    for k in range(1, 26):  # tester toutes les tailles possibles pour la cle
        tab = [""] * k
        somme_IC = 0.0

        for i in range(len(cipher)):
            tab[i % k] += cipher[i]

        for j in range(k):
            somme_IC += indice_coincidence(freq(tab[j]))

        moy = somme_IC / k

        if moy > 0.06:  # si la moyenne IC > 0.06 alors on a trouve la cle on la retourne directement
            return k

    return 0  # si aucune taille n'est satisfaisante
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    Retourne la clé probable en colonnes via la lettre la plus fréquente
    """

    decalages=[0]*key_length
    tab=[""]*key_length  #stocker les colonnes du cipher, selon la taille de la cle 
    #construire les colonnes
    for i in  range(len(cipher)):
        tab[i%key_length]+=cipher[i]
    #pour chaque colonne
    #je regarde la lettre qui apparait le plus 
    #je calcule le decalage qui est stocke dans ordd
    for i in range(key_length):
        lettre = lettre_freq_max(tab[i])  
        decalages[i] = (lettre - (ord('E') - ord('A'))) % 26 

    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    Réalise une première cryptanalyse du texte cipher via l’indice de coïncidence
    """

    cle_taille=longueur_clef(cipher)

    decalage=clef_par_decalages(cipher, cle_taille)

    res = ""

    for i in range(len(cipher)):
        j = (ord(cipher[i]) - ord('A') - decalage[i % len(decalage)]) % 26
        res += chr(j + ord('A'))

    return res


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Calcule l'indice de coïncidence mutuelle (ICM) entre deux textes représentés
    par leurs histogrammes de fréquences h1 et h2, en appliquant un décalage d
    sur le deuxième texte (comme un chiffrement de César).
    """

    if len(h1) != len(h2):
        return 0.0
    
    #le nombre total de caracteres de h1 et h2
    nb_h1 = sum(h1)
    nb_h2 = sum(h2)

    if nb_h1 == 0 or nb_h2 == 0:  #si l un des textes est vide
        return 0.0
    
    s = 0.0 #le IC final

    # h2 est decale de d position donc (i+d)%26 (circulaire)
    for i in range(len(h1)):
        s += h1[i] * h2[(i+d)%26]

    return s / (nb_h1 * nb_h2)

# Renvoie le tableau des décalages probables étant
# donné la longueur de la cl
# en comparant l'indice de déécalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Calcule le décalage relatif de chaque colonne d'un texte chipher
    par rapport à la première colonne en utilisant l'indice de coïncidence mutuelle (ICM)
    """
    decalages=[0]*key_length

    tab=[""]*key_length  #stocker les colonnes du cipher, selon la taille de la cle 
    #construire les colonnes
    for i in  range(len(cipher)):
        tab[i%key_length]+=cipher[i].upper()   

    decalages[0] = 0  #la premiere colonne utilisee comme reference
    h1 = freq(tab[0]) #recuperer la frequence de la premiere colonne

    for i in range(1, key_length):
        best_icm = -1.0    #pour sauvegarder le icm maximal
        best_d = 0   #pour sauvegarder le decalage d qui donne le icm maximal
        h2 = freq(tab[i])   #tableau de frequence de la colonne ieme
        for d in range(26):  #tester tous les d possible sur la ieme colonne
            icm = indice_coincidence_mutuelle(h1, h2, d)
            #pour chaque d je calcule le icm et je sauvegarde le maximal
            if icm > best_icm:
                best_icm = icm
                best_d = d
        decalages[i] = best_d
 
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Réalise la cryptanalyse d'un texte chiffré cipher en utilisant l'indice
    de coïncidence mutuelle (ICM) pour aligner les colonnes
    """

    #deduire la taille de la cle avec IC
    cle_taille=longueur_clef(cipher)

    #calculer les decalages relatifs avec ICM
    decalages = tableau_decalages_ICM(cipher, cle_taille)

    #recuperer les colonnes pour les decaler
    tab=[""]*cle_taille  #stocker les colonnes du cipher, selon la taille de la cle 
    #construire les colonnes
    for i in  range(len(cipher)):
        tab[i%cle_taille]+=cipher[i].upper()  

    #décaler chaque colonne pour l’aligner avec la première colonne
    #donc annuler le decalage de d=decalages[i] par rapport a la 1ere colonne
    #donc si decalee de +d il faut faire -d pour annuler ce decalage avec cesar en modulo 26 
    for i in range(1, cle_taille):
        tab[i] = dechiffre_cesar(tab[i], decalages[i]) 

    #maintenant les colonnes sont chiffrees par cesar

    # On defini des compteurs pour savoir quelle lettre on prend dans chaque colonne
    indices_colonnes = [0] * cle_taille
    texte = "" # On commence avec une chaîne vide 
    for i in range(len(cipher)):
        num_colonne = i % cle_taille
    
         # On récupère la lettre dans la colonne correspondante
        lettre = tab[num_colonne][indices_colonnes[num_colonne]]
    
         # On l'ajoute directement à notre texte final
        texte += lettre
    
        # On avance le compteur pour cette colonne précise
        indices_colonnes[num_colonne] += 1
    

    #déchiffrer le texte chiffré en César
    lettre_max=lettre_freq_max(texte)
    cle_cesar=(lettre_max-4)%26 #Calculer le décalage global par rapport à la lettre 'E' (indice 4)

    return dechiffre_cesar(texte, cle_cesar)


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    prend deux listes de même longueur, correspondant à deux
    variables aléatoires, et renvoie la valeur de la corrélation entre 
    les deux.
    """

    if L1==[] or L2==[]:
        return 0.0
    
    if len(L1)!=len(L2):
        return 0.0
    moy1=sum(L1)/len(L1)
    moy2=sum(L2)/len(L2)
    somme_enum=0
    somme_carre_x=0
    somme_carre_y=0
    for i in range(len(L1)):
        somme_enum+=(L1[i]-moy1)*(L2[i]-moy2)
        somme_carre_x+=(L1[i]-moy1)**2
        somme_carre_y+=(L2[i]-moy2)**2

    if somme_carre_y*somme_carre_x==0:
        return 0.0
    return somme_enum/math.sqrt(somme_carre_x*somme_carre_y)

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
     étant donné un texte chiffré et une taille de clef, calcule
    pour chaque colonne le décalage qui maximise la corrélation avec un texte français
    """


    key=[0]*key_length
    tab=[""]*key_length #extraire les colonnes du texte
        
    score=0.0

    for i in range(len(cipher)):
        tab[i%key_length]+=cipher[i]

    #calculer le decalage qui maximise la correlation pour chaque colonne

    for i in range (key_length):
        best_d=-1 #contient le meilleur decalage
        best_corr=0.0 #contient la meilleur correlation
        
        occ_colonne=freq(tab[i])# la fonction freq renvoie les occurrences
        freq_colonne=[x/len(tab[i]) for x in occ_colonne]


        for d in range(0, 26):
            # ON decale le tableau de fréquences de la colonne de d cases
            # pour voir si ça correspend avec le français (freq_FR)   
            #         
            freq_decalee = [ freq_colonne[(j + d) % 26] for j in range(26) ]
            corr=correlation(freq_FR, freq_decalee)
            if (corr>best_corr and corr<=1):
                best_d=d
                best_corr=corr
        key[i]=best_d
        score+=best_corr
    score /=key_length
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Cryptanalyse un texte en testant toutes les tailles de clefs de 1 à 20.
    La meilleure taille est celle qui donne la meilleure corrélation de Pearson moyenne.
    """
    

    meilleur_score = -1.0
    meilleure_cle = []

    # on teste toutes les longueurs de clef de 1 à 20
    for longueur in range(1, 21):
        # on utilise la fonction de la Question 14
        score_moyen, cle_potentielle = clef_correlations(cipher, longueur)
        
        # on garde la longueur qui donne le meilleur "match" avec le français
        if score_moyen > meilleur_score:
            meilleur_score = score_moyen
            meilleure_cle = cle_potentielle

    # Une fois la boucle finie, on déchiffre avec la clé gagnante
    return dechiffre_vigenere(cipher, meilleure_cle)


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
