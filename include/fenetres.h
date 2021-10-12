#ifndef FENETRES_H

    #define FENETRES_H
        #ifdef _WIN32
        	#include <windows.h>
    	#endif
   
    #include <stdio.h>
    #include <gtk/gtk.h>
    #include <stdbool.h>
    #include <unistd.h>
    #include <gcrypt.h>
   
    //------Utile pour cryptage
    #define NEED_LIBGCRYPT_VERSION "1.8.5"
    #define GCRY_CIPHER GCRY_CIPHER_AES256   // Pick the cipher here
    #define GCRY_C_MODE GCRY_CIPHER_MODE_CBC // Pick the cipher mode here ECB
    //------Utile pour cryptage

    //-----Utile pour bouton
    #define BOUTONS_ACTIVER_TOUT 1
    #define BOUTONS_DESACTIVER_TOUT 0
    #define BOUTONS_ACTIVER_SELECTION 2
    //-----Utile pour bouton

    #define ERREUR 0
    #define NERREUR 1
   
    typedef struct buttons_struct{//contient les boutons à passer entre les fonctions
     GtkWidget* button_crypt;
     GtkWidget* button_decrypt;
     GtkWidget* button_select;
    }buttons_struct;
      
    typedef struct info_struct{//contient info general à passer entre les fonctions
     char* filename;
     GtkTextBuffer* buffer;
     GtkWidget *progress_bar;
     double progress_bar_valeur;
     bool Suppression; //pour suppression du fichier source
     char password[32];//Contient mot de passe
     gcry_cipher_hd_t gcryCipherHd;
     buttons_struct buttons;
    }info_struct;


    void ScrollToEnd(GtkWidget*, GtkAdjustment*);
    //ascenseur de la console descend automatiquement

    void ouverture_fichier(GtkWidget*, info_struct*);

    void crypter(GtkWidget*, info_struct*);
    //Appelle l'ouverture du thread correspondant

    void decrypter(GtkWidget*, info_struct*);
    //Appelle l'ouverture du thread correspondant

    void modification_boutons(info_struct*, int);
    //active/désactive bouton suivant valeur

    void close_window(GtkWidget*, gpointer);//Fermer pop-up

    void PassValide(GtkWidget*, info_struct*);//appuie bouton validation mot de passe entré

    int CryptPassword (GtkWidget *, info_struct*);//Fenetre demandant le mot de passe

    void barre_avancement(info_struct*, double);//augmente valeur de la barre de progression
      
    #if defined (_WIN32)
        void arguments(int, char*[], info_struct*);//Gestion des arguments, necessite réécriture des fonctions pour bypass GTK
        void fermer_console(bool);//fermer console avec EXIT_SUCCESS oou EXIT_FAILURE
    #elif defined (__linux__)
		void arguments(int, char*[], info_struct*);
	#endif
      
#endif