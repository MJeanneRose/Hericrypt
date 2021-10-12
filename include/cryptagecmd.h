#ifndef CRYPTOCMD_H
    #define CRYPTOCMD_H

    //#ifdef _WIN32
    #include "../include/cryptage.h"
         
    int Crypt_cmd(void*, bool);//Fonction de chiffrement par ligne de commande (bool = verbeux)
      
    int PassValide_cmd(info_struct*);//Demande de mot de passe si ligne de commande

    long get_buffer_cmd(info_struct*, unsigned char**, const long, bool);

    int copie_donnees_cmd(FILE*, FILE*, unsigned char*,const long, char*, int*, info_struct*, bool);
        int chiffrement_cmd(unsigned char*, long, info_struct*, bool);

    //#endif
#endif