#ifndef CRYPTO_H
    #define CRYPTO_H

    //#ifdef _WIN32
    #include "../include/fenetres.h"
    #include <sys/types.h>
    #include <sys/stat.h>
      
    int Crypt(void*);
    //Fonction creation process
         
        int get_nom_ext(const char*, char**, char**, char**);
        //a partir du chemin complet (chemin+nom+ext) récupère : nom, extension, chemin

        long get_taille_fichier(FILE*);
        //retourne la taille du fichier (nombre d'octets)

        long get_buffer(info_struct*, unsigned char**, const long);
        //alloue buffer de la plus grande taille possible et multiple de 16 pour cryptage, retourne nombre d'iteration et 0 si allocation impossible

        //copie données du fichier source au fichier cible en chiffrant au passage
        int copie_donnees(FILE*, FILE*, unsigned char*,const long, char*, int*, info_struct*);
            int chiffrement(unsigned char*, long, info_struct*);

      //#endif
#endif