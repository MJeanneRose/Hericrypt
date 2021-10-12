#ifndef DECRYPTOCMD_H
    #define DECRYPTOCMD_H

    //#ifdef _WIN32
    #include "../include/cryptagecmd.h"
    #include "../include/decryptage.h"

    int Decrypt_cmd(void*, bool);
         
    int copie_donnees_vidage_cmd(FILE*, FILE*, unsigned char*, const long, const long, info_struct*, bool);
    //copie données depuis le fichier source vers un fichier de vidage (enlevement taille remplissage)

    int dechiffrement_cmd(unsigned char*, long, info_struct*, bool);

    int copie_donnees_final_cmd(FILE*, FILE*, unsigned char*,const long, const long, info_struct*, bool);
    //copie données depuis le fichier vidage vers fichier final

    long get_buffer_decrypt_cmd(info_struct*, unsigned char**, const long, bool);
    //alloue buffer de la plus grande taille possible, retourne nombre d'iteration et 0 si allocation impossible

    //#endif
#endif