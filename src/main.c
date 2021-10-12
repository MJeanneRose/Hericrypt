/*************AES256*************/
/*
    Jeanne-Rose Méven
    12/2020
*/
/*************AES256*************/

#include "../include/fenetres.h"

int main(int argc, char* argv[])
{
    info_struct info = {NULL,NULL,NULL,0.0, FALSE};

    /*------------LIBGCRYPT------------*/
    gcry_error_t     gcryError;

    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION))
    {
        printf("Le programme ne possède pas la version libgcrypt minimum requise...\n");
        printf("Version minimum demandée : 1.8.5\n");
        printf("Version actuelle : %s\n",gcry_check_version(NULL));
    }
    gcry_control (GCRYCTL_DISABLE_SECMEM);
  
    //Tell Libgcrypt that initialization has completed.
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  
    gcryError = gcry_cipher_open(
        &info.gcryCipherHd, // gcry_cipher_hd_t *
        GCRY_CIPHER,   // int
        GCRY_C_MODE,   // int
        GCRY_CIPHER_SECURE);            // unsigned int
    if (gcryError)
    {
        printf("Echec.\n");
        printf("%s",gcry_strsource(gcryError));
        printf("%s",gcry_strerror(gcryError));
    }
    /*---------END LIBGCRYPT-----------*/

    if(argc > 1){//si lancé en ligne de commande
        arguments(argc, argv, &info);
    }
  
    GtkWidget *window;
    GtkWidget *vbox;
    GtkWidget* scrolledwindow;
    GtkAdjustment *adj=NULL;
    GtkWidget *view;
    GtkWidget *hbox;

    gtk_init (&argc, &argv);
    /*------------CSS-----------*/
  
    GtkCssProvider *provider;
    GdkDisplay *display;
    GdkScreen *screen;

    provider = gtk_css_provider_new ();
    display = gdk_display_get_default ();
    screen = gdk_display_get_default_screen (display);

    GError *error = 0;

     gtk_css_provider_load_from_data (GTK_CSS_PROVIDER (provider),
                                  "* {"
                                  "  padding-top: 0;"
                                  "  padding-left: 0;"
                                  "  padding-right: 0;"
                                  "  padding-bottom: 0;"
                                  "  background-color: black;"
                                  "  color: white;"
                                  "  border-color: white;"
                                  "}"
                                  "*:disabled {"//remplacer par :insensitive si problème
                                  "  color: rgba(50%,50%,50%,0.75);"
                                  "}"
                                  ".entry {"
                                  "  color: black;"
                                  "}"
                                  "GtkProgressBar  {"
                                  "  color: black;"
                                  "}"
                                  , -1, &error);
                              
    gtk_style_context_add_provider_for_screen (screen, GTK_STYLE_PROVIDER (provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref (provider);
    /*--------END CSS---------*/

    //FENETRE
    window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title (GTK_WINDOW (window), "HeriCrypt v1.6");
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
    gtk_widget_set_size_request(window, 500, 300);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);

    g_signal_connect (window, "destroy", G_CALLBACK (gtk_main_quit), NULL);

    //BOX verticale : console texte, barre progression, boutons
    vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);//10: espacement entre les enfants
    gtk_container_add (GTK_CONTAINER (window), vbox);
  
    //CONSOLE DE TEXTE
    view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view),GTK_WRAP_WORD);
    scrolledwindow = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request (scrolledwindow,500,200);
    g_signal_connect (scrolledwindow, "size-allocate", G_CALLBACK (ScrollToEnd), adj);
    gtk_container_add(GTK_CONTAINER(scrolledwindow), view);
    info.buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_view_set_editable (GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), scrolledwindow, FALSE, TRUE, 5);

    //Barre de progression
    info.progress_bar = gtk_progress_bar_new ();
    gtk_box_pack_start(GTK_BOX(vbox), info.progress_bar, FALSE, TRUE, 5);
    gtk_progress_bar_set_show_text (GTK_PROGRESS_BAR(info.progress_bar),TRUE);

    //Bouton CRYPTER
    info.buttons.button_crypt = gtk_button_new_with_label ("Crypter");
    g_signal_connect (info.buttons.button_crypt, "clicked", G_CALLBACK (crypter), &info);

    //BOX d'alignement boutons
    hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0); //0 : espace entre enfants
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE, 5);
    gtk_box_pack_start(GTK_BOX(hbox), info.buttons.button_crypt, TRUE, TRUE, 0);

    /*Bouton DECRYPTER*/
    info.buttons.button_decrypt = gtk_button_new_with_label ("Decrypter");
    g_signal_connect (info.buttons.button_decrypt, "clicked", G_CALLBACK (decrypter), &info);
    gtk_box_pack_start(GTK_BOX(hbox), info.buttons.button_decrypt, TRUE, TRUE, 0);

    /*Bouton selection fichier*/
    info.buttons.button_select = gtk_button_new_with_label("Selection fichier");
    g_signal_connect (info.buttons.button_select, "clicked", G_CALLBACK (ouverture_fichier), &info);
    gtk_box_pack_start(GTK_BOX(hbox), info.buttons.button_select, TRUE, TRUE, 0);

    gtk_widget_show_all (window);
  
    /*---------INIT CHIFFREMENT---------*/
  
    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION))
    {
        gtk_text_buffer_insert_at_cursor (info.buffer,"Le programme ne possède pas la version libgcrypt minimum requise...\n",-1);
        gtk_text_buffer_insert_at_cursor (info.buffer,"Version minimum demandée : 1.8.6\n",-1);
        gtk_text_buffer_insert_at_cursor (info.buffer,"Version actuelle : ",-1);
        gtk_text_buffer_insert_at_cursor (info.buffer,gcry_check_version(NULL),-1);
        gtk_text_buffer_insert_at_cursor (info.buffer,"\n",-1);
    }
    gtk_text_buffer_insert_at_cursor (info.buffer,"Initialisation ... ",-1);

    if (gcryError)
    {
        gtk_text_buffer_insert_at_cursor (info.buffer,"Echec.\n ",-1);
        gtk_text_buffer_insert_at_cursor (info.buffer,gcry_strsource(gcryError),-1);
        gtk_text_buffer_insert_at_cursor (info.buffer,gcry_strerror(gcryError),-1);
    }
  
    gtk_text_buffer_insert_at_cursor (info.buffer,"Ok.\n",-1);
  
    /*-------END INIT CHIFFREMENT---------*/
  
    gtk_main ();

    return 0;
}
