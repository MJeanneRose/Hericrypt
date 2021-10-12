#include "../include/fenetres.h"
#include "../include/cryptage.h"
#include "../include/cryptagecmd.h"
#include "../include/decryptage.h"
#include "../include/decryptagecmd.h"
  
void ScrollToEnd (GtkWidget *widget, GtkAdjustment* adj)
{
    adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW (widget));
    gtk_adjustment_set_value (adj, gtk_adjustment_get_upper (adj));
}

void crypter (GtkWidget *widget, info_struct* info)
{
    if(!CryptPassword (widget, info))
    {
        GThread *thread = NULL;
        gtk_text_buffer_insert_at_cursor (info->buffer,"Lancement du thread de chiffrement... ",-1);
        thread = g_thread_try_new ("Chiffrement", (GThreadFunc)Crypt, (gpointer)info, NULL);
        if(thread == NULL)
            gtk_text_buffer_insert_at_cursor (info->buffer,"Echec.\n",-1);
    }
}

void decrypter (GtkWidget *widget, info_struct* info)
{
    if(!CryptPassword (widget, info))
    {
        GThread *thread = NULL;
        gtk_text_buffer_insert_at_cursor (info->buffer,"Lancement du thread de déchiffrement... ",-1);
        thread = g_thread_try_new ("Dechiffrement", (GThreadFunc)Decrypt, (gpointer)info, NULL);
        if(thread == NULL)
            gtk_text_buffer_insert_at_cursor (info->buffer,"Echec.\n",-1);
    }
}

void ouverture_fichier (GtkWidget *widget, info_struct* info)
{
    GtkWidget *dialog;

    dialog = gtk_file_chooser_dialog_new ("Ouvrir un fichier",
                                          NULL,
                                          GTK_FILE_CHOOSER_ACTION_OPEN,
                                          "Annuler",GTK_RESPONSE_CANCEL,
                                          "Ouvrir", GTK_RESPONSE_ACCEPT,
                                          NULL);

    if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
    {
        info->filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
        gtk_text_buffer_insert_at_cursor (info->buffer,"Importation reussie :\n",-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,info->filename,-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
        modification_boutons(info, BOUTONS_ACTIVER_TOUT);
        info->progress_bar_valeur = 0.0;
        gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR(info->progress_bar),info->progress_bar_valeur);
    }
    gtk_widget_destroy(dialog);
}

void modification_boutons(info_struct* info, int valeur)
{
    switch(valeur)
    {
        case 0 ://désactive tout les boutons
             gtk_widget_set_sensitive (info->buttons.button_select, false);
             gtk_widget_set_sensitive (info->buttons.button_crypt, false);
             gtk_widget_set_sensitive (info->buttons.button_decrypt, false);
             break;
        case 1 ://activer tout les boutons
             gtk_widget_set_sensitive (info->buttons.button_select, true);
             gtk_widget_set_sensitive (info->buttons.button_crypt, true);
             gtk_widget_set_sensitive (info->buttons.button_decrypt, true);
             break;
        case 2 ://active seulement selection
             gtk_widget_set_sensitive (info->buttons.button_select, true);
             gtk_widget_set_sensitive (info->buttons.button_crypt, false);
             gtk_widget_set_sensitive (info->buttons.button_decrypt, false);
             break;
    }
}

void PassValide(GtkWidget *widget, info_struct* info)
{
    const gchar *temp;
    gcry_error_t     gcryError;
    // recupere la chaine contenu dans l'entree
    temp = gtk_entry_get_text(GTK_ENTRY(widget));

    guint16 taille = gtk_entry_get_text_length (GTK_ENTRY(widget));

    int i;
    for(i = 0;i<taille;i++)
        info->password[i] = temp[i];
      
    for(int j = i; j<32;j++)
        info->password[j] = '1';//remplissage avec des '1' si mot de passe trop court
      
    size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    gcryError = gcry_cipher_setkey(info->gcryCipherHd, info->password, keyLength);
      
    if (gcryError)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : mot de passe.\n",-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strsource(gcryError),-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strerror(gcryError),-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
        return;
    }
    gtk_text_buffer_insert_at_cursor (info->buffer,"Mot de passe : Ok.\n",-1);
}

int CryptPassword (GtkWidget *widget, info_struct* info)
{
    GtkWidget *Dialogue;
    GtkWidget *content_area;
    GtkWidget *passWord;
    GtkWidget *check;//checkbox suppression fichier

    Dialogue = gtk_dialog_new();
    gtk_window_set_title (GTK_WINDOW(Dialogue), "Mot de passe");
    gtk_window_set_position(GTK_WINDOW(Dialogue), GTK_WIN_POS_CENTER);
    gtk_widget_set_size_request(Dialogue, 300, 90);
                                      
    content_area = gtk_dialog_get_content_area (GTK_DIALOG (Dialogue));                            
    //g_signal_connect(Dialogue, "destroy", G_CALLBACK (close_window), NULL);

    passWord = gtk_entry_new();
    gtk_container_add (GTK_CONTAINER (content_area), passWord);
    gtk_entry_set_max_length (GTK_ENTRY(passWord), 32); //32 octets pour chiffrement
    gtk_entry_set_visibility (GTK_ENTRY(passWord), false);

    gtk_widget_show(passWord);

    gtk_dialog_add_button (GTK_DIALOG(Dialogue), "Valider", GTK_RESPONSE_ACCEPT);//gint response_id);

    check = gtk_check_button_new_with_label ("effacer fichier");
    gtk_container_add (GTK_CONTAINER (content_area), check);
    gtk_widget_show(check);

    int result = gtk_dialog_run (GTK_DIALOG (Dialogue));
   
    switch (result)
    {
        case GTK_RESPONSE_ACCEPT:
            // do_application_specific_something ();
            PassValide(passWord, info);
            if(gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON(check)))
             info->Suppression = TRUE;
            gtk_widget_destroy (Dialogue);
            return 0;
        default:
            // do_nothing_since_dialog_was_cancelled ();
            gtk_widget_destroy (Dialogue);
            return 1;
    }
}

void barre_avancement(info_struct* info, double ajout)
{
   info->progress_bar_valeur+= ajout;
   gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR(info->progress_bar),info->progress_bar_valeur);
}

#if defined (_WIN32)
void arguments(int argcount, char* argval[], info_struct* info)
{
    int opt;
    bool v = FALSE;//mode verbeux
    int choix = 42;//42 aucun arguments 0 chiffrement 1 dechiffrement
    if(!AllocConsole())
        exit(EXIT_FAILURE);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    freopen("CONIN$", "r", stdin);
   
    while ((opt=getopt(argcount, argval, "hvsc:d:")) != -1)
    {
        switch (opt)
        {
            case 'c'://Chiffrement
                if(choix == 1)
                {
                    printf("Arguments -c et -d incompatible.\n");
                    fermer_console(ERREUR);
                }
                choix = 0;
                info->filename = malloc(sizeof(char)*strlen(optarg));
                strcpy(info->filename, optarg);
                break;
            case 'd'://Déchiffrement
                if(choix == 0)
                {
                    printf("Arguments -c et -d incompatible.\n");
                    fermer_console(ERREUR);
                }
                choix = 1;
                info->filename = malloc(sizeof(char)*strlen(optarg));
                strcpy(info->filename, optarg);
                break;
            case 'h'://help
                printf("Usage : %s [OPTIONS] [FICHIER]\nOptions : \n  -c Chiffre le fichier\n  -d Dechiffre le fichier\n  -s Supprime le fichier source\n  -v Mode verbeux\n",argval[0]);
                fermer_console(NERREUR);
            case 's'://Suppression
                info->Suppression = TRUE;
                break;
            case 'v'://mode verbeux
                v = TRUE;
                break;
            default: /* '?' */
                if(optopt == 'c' || optopt == 'd')
                    printf("\nSyntaxe incorrect.\n");
                printf("Tapez -h pour obtenir de l'aide.\n");
                fermer_console(ERREUR);
        }
    }
    if(choix == 1)//dechiffrement
    {
        printf("Lancement du dechiffrement de %s ...\n",info->filename);
        if(Decrypt_cmd(info, v))
            fermer_console(ERREUR);
    }
    else if(choix == 0)//chiffrement
    {
        printf("Lancement du chiffrement de %s ...\n",info->filename);
        if(Crypt_cmd(info, v))
            fermer_console(ERREUR);
    }
    else//42 = seulement suppression et ou verbeux
    {
        printf("\nSyntaxe incorrect.\nTapez -h pour obtenir de l'aide\n");
        fermer_console(ERREUR);
    }
    fermer_console(NERREUR);   
}

void fermer_console(bool succes)
{
   system("PAUSE");
   FreeConsole();
   if(succes)
      exit(EXIT_SUCCESS);
   exit(EXIT_FAILURE);
}

#elif defined (__linux__)
void arguments(int argcount, char* argval[], info_struct* info)
{
    int opt;
    bool v = FALSE;//mode verbeux
    int choix = 42;//42 aucun arguments 0 chiffrement 1 dechiffrement
   
    while ((opt=getopt(argcount, argval, "hvsc:d:")) != -1)
    {
        switch (opt)
        {
            case 'c'://Chiffrement
                if(choix == 1)
                {
                    printf("Arguments -c et -d incompatible.\n");
                    exit(EXIT_FAILURE);
                }
                choix = 0;
                info->filename = malloc(sizeof(char)*strlen(optarg));
                strcpy(info->filename, optarg);
                break;
            case 'd'://Déchiffrement
                if(choix == 0)
                {
                    printf("Arguments -c et -d incompatible.\n");
                    exit(EXIT_FAILURE);
                }
                choix = 1;
                info->filename = malloc(sizeof(char)*strlen(optarg));
                strcpy(info->filename, optarg);
                break;
            case 'h'://help
                printf("Usage : %s [OPTIONS] [FICHIER]\nOptions : \n  -c Chiffre le fichier\n  -d Dechiffre le fichier\n  -s Supprime le fichier source\n  -v Mode verbeux\n  -h Affiche l'aide\n",argval[0]);
                exit(EXIT_SUCCESS);
            case 's'://Suppression
                info->Suppression = TRUE;
                break;
            case 'v'://mode verbeux
                v = TRUE;
                break;
            default: /* '?' */
                if(optopt == 'c' || optopt == 'd')
                    printf("\nSyntaxe incorrect.\n");
                printf("Tapez -h pour obtenir de l'aide.\n");
                exit(EXIT_FAILURE);
        }
    }
    if(choix == 1)//dechiffrement
    {
        printf("Lancement du dechiffrement de %s ...\n",info->filename);
        if(Decrypt_cmd(info, v))
            exit(EXIT_FAILURE);
    }
    else if(choix == 0)//chiffrement
    {
        printf("Lancement du chiffrement de %s ...\n",info->filename);
        if(Crypt_cmd(info, v))
            exit(EXIT_FAILURE);
    }
    else//42 = seulement suppression et ou verbeux
    {
        printf("\nSyntaxe incorrect.\nTapez -h pour obtenir de l'aide\n");
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);  
}
#endif