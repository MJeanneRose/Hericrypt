#ifndef DECRYPTO_H
    #define DECRYPTO_H

    #include "../include/cryptage.h"
      
    int Decrypt(void*);
         
        int get_nom(const char*, char**, const char*, int, info_struct*);
        //a partir du chemin complet (chemin+nom+ext) récupère : chemin+nom
        //Cette fonction est une modification de celle présente dans cryptage.h (non récupération de l'extension puisque inscrite dans le fichier

        int copie_donnees_vidage(FILE*, FILE*, unsigned char*, const long, const long, info_struct*);
        //copie données depuis le fichier source vers un fichier de vidage (enlevement taille remplissage)

        int dechiffrement(unsigned char*, long, info_struct*);

        int copie_donnees_final(FILE*, FILE*, unsigned char*,const long, const long, info_struct*);
        //copie données depuis le fichier vidage vers fichier final

        long get_buffer_decrypt(info_struct*, unsigned char**, const long);
        //alloue buffer de la plus grande taille possible, retourne nombre d'iteration et 0 si allocation impossible
         
#endif