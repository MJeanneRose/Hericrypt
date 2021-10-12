//#ifdef _WIN32

   #include "../include/cryptagecmd.h"

int Crypt_cmd(void* data, bool verbeux)
{
    info_struct * info = (info_struct*)data;
    if(verbeux)printf("Ouverture du fichier a crypter... ");

    FILE* source;

    source = fopen(info->filename,"rb");
    if(source == NULL)
    {
        printf("Erreur ouverture du fichier source.\n");
        return 1;
    }
    if(verbeux)printf("Ok.\n");

    if(PassValide_cmd(info))return 1;

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

    //-----OBTENTION NOMS--------
    if(get_nom_ext(info->filename, &nom, &nomExtension, &chemin))
    {
        printf("Erreur d'obtention du nom de fichier (allocation memoire).\n");
        fclose(source);
        return 1;
    }
    //-----END OBTENTION NOMS----

    //-----OUVERTURE FICHIER FINAL-----
      
     if(chemin != NULL)
    {
        nomCopie = malloc(sizeof(char)*(strlen(chemin)+strlen(nom)+11));//+11 = .hericrypt'\0'
    }
    else
        nomCopie = malloc(sizeof(char)*(strlen(nom)+11));//+11 = .hericrypt'\0'
         
      
    if(nomCopie == NULL)
    {
        printf("Erreur nom de fichier (allocation memoire).\n");
        fclose(source);
        free(nom);
        free(chemin);
        free(nomExtension);
        return 1;
    }
      
    if(verbeux)printf("Creation du fichier : ");
      
    if(chemin !=NULL)
    {
        strcpy(nomCopie, chemin);
        strcat(nomCopie, nom);
    }
    else
        strcpy(nomCopie, nom);
      
    strcat(nomCopie, ".hericrypt");
      
    if(verbeux)printf("%s ... ",nomCopie);
      
    cible = fopen(nomCopie,"wb");
      
    if(cible == NULL)
    {
        printf("Erreur creation du fichier cible.\n");
        fclose(source);
        free(nom);
        free(chemin);
        free(nomExtension);
        free(nomCopie);
        return 1;
    }
    if(verbeux)printf("Ok.\n");
    //----END OUVERTURE FICHIER FINAL--

    free(nom);
    free(chemin);

    //-----OBTENTION DES TAILLES-------
    taille_fichier = get_taille_fichier(source);
    taille_total = taille_fichier + (long)strlen(nomExtension)+(long)1; 
    taille_buffer = get_buffer_cmd(info, &buffer_fichier, taille_total, verbeux);
      
    if(taille_buffer == 0)
    {
        printf("Erreur : obtention du buffer.\n");
        fclose(source);
        fclose(cible);
        free(nomExtension);
        remove(nomCopie);
        free(nomCopie);
        return 1;
    }
    //-----END OBTENTION DES TAILLES----
      
    //--------VECTEUR INITIALISATION-------
    gcry_create_nonce(InitVector, 16);

    gcryError = gcry_cipher_setiv(info->gcryCipherHd, InitVector, blkLength);
    if (gcryError)
    {
        printf("Erreur : vecteur initialisation.\n");
        printf("%s\n",gcry_strsource(gcryError));
        printf("%s\n",gcry_strerror(gcryError));
        return 1;
    }
    if(verbeux)printf("Vecteur d'initialisation : Ok.\n");
      
    //----END VECTEUR INITIALISATION-------

    if(copie_donnees_cmd(source, cible, buffer_fichier, taille_buffer, nomExtension, &remplissage, info, verbeux)){
        free(buffer_fichier);
        free(InitVector);
        fclose(source);
        fclose(cible);
        remove(nomCopie);
        free(nomExtension);
        free(nomCopie);
    }
      
    sprintf(temp,"%X",remplissage);
    fwrite(temp,1,sizeof(char),cible);//valeur de remplissage
    fwrite(InitVector,16,sizeof(unsigned char),cible);
    printf("Chiffrement termine.\n");

    fclose(cible);
    free(nomExtension);
    free(nomCopie);
    free(buffer_fichier);
    fclose(source);
    free(InitVector);
      
    if(info->Suppression)
    {
        if(verbeux)printf("Supression fichier source... ");
        remove(info->filename);
        if(verbeux)printf("Ok.\n");
    }
      
    free(info->filename);
    return 0;
}
   
long get_buffer_cmd(info_struct* info, unsigned char** buffer_fichier, const long taille_fichier, bool verbeux)
{
    if(verbeux)printf("Allocation memoire du buffer...\n");
    long taille_buffer;
      
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
        if(verbeux)printf("\nEchec. Tentative de diminution du buffer... ");
        for(int i = 2; taille_buffer > 16; i++)
        {
            if(((taille_buffer/i)%16)!=0)
               taille_buffer = 16-((taille_buffer/i)%16)+(taille_buffer/i);
               
            *buffer_fichier = (unsigned char*)malloc(taille_buffer*sizeof(unsigned char));
               
            if(*buffer_fichier != NULL)
            {
               if(verbeux)printf("Ok\n");
               break;
            }
        }
    }
    if(verbeux)printf("Taille du buffer : %ld octets.\n", taille_buffer);
    if(*buffer_fichier == NULL)
    {
            if(verbeux)printf("Echec d'allocation memoire.\n");
            taille_buffer = 0;
    }
    else
        if(verbeux)printf("Allocation memoire Ok.\n");
    return taille_buffer;
}
   
int copie_donnees_cmd(FILE* source, FILE* cible, unsigned char* buffer_fichier,const long taille_buffer, char* nomExtension, int* remplissage, info_struct* info, bool verbeux)
{
    if(verbeux)printf("Chiffrement... ");
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
            
        }
        //---END si fin de fichier ----------
         
        //------CHIFFREMENT
         if(chiffrement_cmd(buffer_fichier, taille_buffer, info, verbeux))
         {
            if(verbeux)printf("Abandon.");
            return 1;
         }
         fwrite(buffer_fichier,1,taille_buffer,cible);
    }while(feof(source)==0);
    return 0;
}

int chiffrement_cmd(unsigned char* buffer, long taille, info_struct* info, bool verbeux)
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
       printf("Erreur : chiffrement.\n");
       printf("%s\n",gcry_strsource(gcryError));
       printf("%s\n",gcry_strerror(gcryError));
       return 1;
    }
    if(verbeux)printf("Ok.\n");
    return 0;
}
   
int PassValide_cmd(info_struct* info)
{    
   
   gcry_error_t     gcryError;
   
   printf("Mot de passe : ");
   if(fgets(info->password,32,stdin) == NULL)
   {
	   printf("Erreur : lecture mot de passe.\n");
	   return 1;
   }
      
   for(int i = strlen(info->password)-1; i<32;i++)//enlève le '\n' et le remplace par 1
      info->password[i] = '1';//remplissage avec des '1' si mot de passe trop court
      
   size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
   gcryError = gcry_cipher_setkey(info->gcryCipherHd, info->password, keyLength);
      
   if (gcryError)
   {
       printf("Erreur : mot de passe.\n");
       printf("%s\n",gcry_strsource(gcryError));
       printf("%s\n",gcry_strerror(gcryError));
       return 1;
   }
   printf("Mot de passe Ok.\n");
   return 0;
}

//#endif