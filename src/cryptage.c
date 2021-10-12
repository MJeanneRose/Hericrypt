//Construction : données, extension, taille extension, remplissage, nombre de bit de remplissage
//Chiffrement : aes 256

   #include "../include/cryptage.h"
   
   //valeur ajout barre de progression différente du déchiffrement
   #define progress_ajout 12.5
   
int Crypt(void* data)
{
    // Doit être la première fonction appelée.
    // Quand cette fonction retourne, le thread prend fin.
    info_struct * info = (info_struct*)data;
    gtk_text_buffer_insert_at_cursor (info->buffer,"Ok\nOuverture du fichier à crypter... ",-1);

    FILE* source;

    source = fopen(info->filename,"rb");
    if(source == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"échec\n",-1);
        return 1;
    }
    modification_boutons(info, BOUTONS_DESACTIVER_TOUT);
    gtk_text_buffer_insert_at_cursor (info->buffer,"Ok\n",-1);
    barre_avancement(info, progress_ajout);

    //-----CREATION VARIABLE-----

    gcry_error_t     gcryError;

    char* nom = NULL;//nomFichier
    char* chemin = NULL;//chemin sans nom
    char* nomExtension = NULL;
    char* nomCopie = NULL;

    FILE* cible;

    long taille_fichier;// en octets
    long taille_total;//pour taille buffer: contient données, nom de l'extension et taille de l'extension

    unsigned char * buffer_fichier = NULL;
    long taille_buffer;//doit être multiple de 16 (chiffrement par bloc)

    char temp[64];//necessaire pour copier nombre de remplissage à la fin du fichier
    int remplissage = 0;//nom de caractère de remplissage

    unsigned char* InitVector = (unsigned char*)malloc(sizeof(unsigned char)*16);
    size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    //-----END CREATION VARIABLE--
    barre_avancement(info, progress_ajout);

    //-----OBTENTION NOMS--------
    if(get_nom_ext(info->filename, &nom, &nomExtension, &chemin))
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur d'obtention du nom de fichier (mémoire).\n",-1);
        fclose(source);
        return 1;
    }
    //-----END OBTENTION NOMS----
    barre_avancement(info, progress_ajout);

    //-----OUVERTURE FICHIER FINAL-----
    nomCopie = malloc(sizeof(char)*(strlen(chemin)+strlen(nom)+11));//+11 = .hericrypt'\0'
  
    if(nomCopie == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur allocation mémoire nom de fichier\n",-1);
        fclose(source);
        free(nom);
        free(chemin);
        free(nomExtension);
        return 1;
    }
  
    gtk_text_buffer_insert_at_cursor (info->buffer,"Création du fichier :\n",-1);
  
    if(chemin !=NULL)
    {
         strcpy(nomCopie, chemin);
         strcat(nomCopie, nom);
    }
    else
        strcpy(nomCopie, nom);
  
    strcat(nomCopie, ".hericrypt");

    gtk_text_buffer_insert_at_cursor (info->buffer,nomCopie,-1);
    gtk_text_buffer_insert_at_cursor (info->buffer," ... ",-1);

    cible = fopen(nomCopie,"wb");
  
    if(cible == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur.\n",-1);
        fclose(source);
        free(nom);
        free(chemin);
        free(nomExtension);
        free(nomCopie);
        return 1;
    }
    gtk_text_buffer_insert_at_cursor (info->buffer,"Ok.\n",-1);
    //----END OUVERTURE FICHIER FINAL--
    barre_avancement(info, progress_ajout);

    free(nom);
    free(chemin);

    //-----OBTENTION DES TAILLES-------
    taille_fichier = get_taille_fichier(source);
    taille_total = taille_fichier + (long)strlen(nomExtension)+(long)1; 
    taille_buffer = get_buffer(info, &buffer_fichier, taille_total);
  
    if(taille_buffer == 0)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : obtention du buffer\n",-1);
        fclose(source);
        fclose(cible);
        free(nomExtension);
        remove(nomCopie);
        free(nomCopie);
        return 1;
    }
    //-----END OBTENTION DES TAILLES----
    barre_avancement(info, progress_ajout);

    //--------VECTEUR INITIALISATION-------
    gcry_create_nonce(InitVector, 16);

    gcryError = gcry_cipher_setiv(info->gcryCipherHd, InitVector, blkLength);
    if (gcryError)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : vecteur d'initialisation.\n",-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strsource(gcryError),-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strerror(gcryError),-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
        return 1;
    }
    gtk_text_buffer_insert_at_cursor (info->buffer,"Vecteur d'initialisation : Ok.\n",-1);
  
    //----END VECTEUR INITIALISATION-------
    barre_avancement(info, progress_ajout);

    if(copie_donnees(source, cible, buffer_fichier, taille_buffer, nomExtension, &remplissage, info))
    {
        free(buffer_fichier);
        free(InitVector);
        fclose(source);
        fclose(cible);
        remove(nomCopie);
        free(nomExtension);
        free(nomCopie);
    }

    free(nomExtension);
    free(nomCopie);
    free(buffer_fichier);
    fclose(source);

    if(info->Suppression)
    {
    remove(info->filename);
    info->Suppression = FALSE;
    }
  
    gtk_text_buffer_insert_at_cursor (info->buffer,"Chiffrement terminé.\n ",-1);
    sprintf(temp,"%X",remplissage);
    fwrite(temp,1,sizeof(char),cible);//valeur de remplissage
    fwrite(InitVector,16,sizeof(unsigned char),cible);

    fclose(cible);
    free(InitVector);

    info->progress_bar_valeur = 1.0;
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR(info->progress_bar),info->progress_bar_valeur);

    g_free(info->filename);

    modification_boutons(info, BOUTONS_ACTIVER_SELECTION);
    return 0;
}
   
int get_nom_ext(const char* chemin_complet, char** nom, char** ext, char** chemin)
{
    int taille=strlen(chemin_complet)-1;//commence à 0

    for(int i = taille;i>=0;i--)
    {
        if(chemin_complet[i]=='.')
        {
            *ext=malloc(sizeof(char)*(taille-i+1));//pour ajout du '\0'
            if(*ext==NULL)
                return 1;
            for(int j = 0;j<=taille-i-1;j++)
            {
                ext[0][j]=chemin_complet[i+j+1];
            }
            ext[0][taille-i]='\0';
        }
        if(chemin_complet[i]=='\\' ||chemin_complet[i]=='/')
        {
            i++;
            *chemin = malloc(sizeof(char)*(i+1));//pour ajout du '\0'
            if(*chemin == NULL)
            {
                if(*ext != NULL)
                    free(*ext);
                return 1;
            }
            strncpy(*chemin,chemin_complet,i);
            chemin[0][i]='\0';//strncpy n'ajoute pas de caractère NULL

            if(*ext==NULL)//Si pas d'extension
                *nom = malloc(sizeof(char)*(taille-i+1));
            else
                *nom = malloc(sizeof(char)*(taille-i-strlen(*ext)+1));
            if(*nom==NULL)
            {
                if(*ext != NULL)
                    free(*ext);
                free(*nom);
                return 1;
            }
            int j = 0;
            while(chemin_complet[i+j]!='.' && chemin_complet[i+j]!='\0')
            {
                nom[0][j]=chemin_complet[i+j];
                j++;
            }
            nom[0][j]='\0';
            break;
        }
    }
    if(*nom == NULL)
    {
        if(*ext != NULL)
        {
        *nom = malloc(sizeof(char)*(taille-strlen(*ext)+1));
        strncpy(*nom,chemin_complet,taille-strlen(*ext));
        nom[0][taille-strlen(*ext)]='\0';
        }
        else
        {
            *nom = malloc(sizeof(char)*(taille+1));
            strncpy(*nom, chemin_complet, taille);
        }
    }
    return 0;
}
   
   long get_taille_fichier(FILE* fichier)
   {
      struct stat buf;
      int fd;
      fd = fileno(fichier);
      fstat(fd,&buf);
      return buf.st_size;
   }
   
long get_buffer(info_struct* info, unsigned char** buffer_fichier, const long taille_fichier)
{
    gtk_text_buffer_insert_at_cursor (info->buffer,"Allocation mémoire du buffer...\n",-1);
    long taille_buffer;
    char temp[64];

    if(taille_fichier%16 == 0)
    {
         *buffer_fichier = (unsigned char*)malloc(taille_fichier*sizeof(unsigned char));
         taille_buffer = taille_fichier;
    }
    else
    {
        taille_buffer = 16-(taille_fichier%16)+taille_fichier;
        *buffer_fichier = (unsigned char*)malloc(taille_buffer*sizeof(unsigned char));
    }
    if(*buffer_fichier == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"\nEchec. Tentative de diminution du buffer...\n",-1);
        for(int i = 2; taille_buffer > 16; i++)
        {
            if(((taille_buffer/i)%16)!=0)
               taille_buffer = 16-((taille_buffer/i)%16)+(taille_buffer/i);
               
            *buffer_fichier = (unsigned char*)malloc(taille_buffer*sizeof(unsigned char));
               
            if(*buffer_fichier != NULL)
            {
               gtk_text_buffer_insert_at_cursor (info->buffer,"Ok\n",-1);
               break;
            }
        }
    }
    gtk_text_buffer_insert_at_cursor (info->buffer,"Taille du buffer : ",-1);
    sprintf(temp,"%ld",taille_buffer);
    gtk_text_buffer_insert_at_cursor (info->buffer,temp,-1);
    gtk_text_buffer_insert_at_cursor (info->buffer," octets.\n",-1);
    if(*buffer_fichier == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Echec d'allocation mémoire.\n",-1);
        taille_buffer = 0;
    }
    else
        gtk_text_buffer_insert_at_cursor (info->buffer,"Allocation mémoire Ok.\n",-1);
    return taille_buffer;
}
   
int copie_donnees(FILE* source, FILE* cible, unsigned char* buffer_fichier,const long taille_buffer, char* nomExtension, int* remplissage, info_struct* info)
{
    gtk_text_buffer_insert_at_cursor (info->buffer,"Chiffrement... \n",-1);
    size_t nbLu;//nombre d'octets lu
    char temp[64];
    do
    {
        nbLu = fread(buffer_fichier,1,taille_buffer,source);

        //----------Si fin de fichier-------------
        if(feof(source))
        {
            size_t i;
            for(i = nbLu;i<strlen(nomExtension)+nbLu;i++)
               buffer_fichier[i] = nomExtension[i-nbLu];
            nbLu = i;
            sprintf(temp,"%lX",strlen(nomExtension));
            buffer_fichier[nbLu]=temp[0];
            nbLu++;
            buffer_fichier[nbLu]='\0';
            for(nbLu=nbLu;nbLu<taille_buffer;nbLu++)
            {
               buffer_fichier[nbLu]='R';//remplissage
               *remplissage+=1;
            }
        }//---END si fin de fichier ----------

        //------CHIFFREMENT
        if(chiffrement(buffer_fichier, taille_buffer, info))
        {
            gtk_text_buffer_insert_at_cursor (info->buffer,"Abandon.",-1);
            return 1;
        }
        fwrite(buffer_fichier,1,taille_buffer,cible);
    }while(feof(source)==0);
    return 0;
}
   
int chiffrement(unsigned char* buffer, long taille, info_struct* info)
{
    gcry_error_t     gcryError;
    
    gcryError = gcry_cipher_encrypt(
        info->gcryCipherHd, // gcry_cipher_hd_t
        buffer,    // void *
        taille,    // size_t
        buffer,    // const void *
        taille);   // size_t
    if (gcryError)
    {
       gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : chiffrement.\n",-1);
       gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strsource(gcryError),-1);
       gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
       gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strerror(gcryError),-1);
       gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
       return 1;
    }
    return 0;
}
