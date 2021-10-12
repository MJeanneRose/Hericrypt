//#ifdef _WIN32

   #include "../include/decryptagecmd.h"
   
int Decrypt_cmd(void* data, bool verbeux)
{
    info_struct * info = (info_struct*)data;
    if(verbeux)printf("Ouverture du fichier a decrypter... ");
     
    FILE* source;
     
    source=fopen(info->filename,"rb");
    if(source == NULL){
        printf("Erreur ouverture du fichier source.\n");
        return 1;
     }
     
    if(verbeux)printf("Ok.\n");
     
    if(PassValide_cmd(info))return 1;
      
     //-----CREATION VARIABLES--------
      
    gcry_error_t     gcryError;
  
    FILE* vidage;//fichier temporaire de vidage
    long taille_fichier;
    int remplissage;
  
    unsigned char* buffer_fichier = NULL;
    long taille_buffer;
    int taille_extension = 0;
    char* nomExtension = NULL;
  
    char* nomCible = NULL;//nom Fichier definitif
    FILE* cible;
  
    unsigned char* InitVector = (unsigned char*)malloc(sizeof(unsigned char)*16);
    size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
    //-----END CREATION VARIABLES----
   
    //----OUVERTURE FICHIER DE VIDAGE
    vidage = fopen("temp","wb+");
    if(vidage == NULL)
    {
        printf("Impossible d'ouvrir le fichier de vidage. Abandon\n");
        fclose(source);
        free(InitVector);
        return 1;
    }
    //----END OUVERTURE FICHIER DE VIDAGE
      
    taille_fichier = get_taille_fichier(source)-17;//- (remplissage + initVector)
     
    //---------TAILLE REMPLISSAGE
    fseek(source,taille_fichier,SEEK_SET);
    if(fscanf(source,"%X",&remplissage) != 1){
		printf("Erreur : obtention valeur de remplissage.\n");
		fclose(source);
		free(InitVector);
		return 1;
	}
    //-----END TAILLE REMPLISSAGE
     
    //---------INIT VECTOR
    fseek(source,taille_fichier+1,SEEK_SET);
    if(fread(InitVector,16,sizeof(unsigned char),source) == '\0'){
		printf("Erreur : lecture du vecteur d'initialisation.\n");
		fclose(source);
		free(InitVector);
        return 1;
	}
      
      
    gcryError = gcry_cipher_setiv(info->gcryCipherHd, InitVector, blkLength);
    if (gcryError)
    {
        printf("Erreur : vecteur initialisation.\n");
        printf("%s\n",gcry_strsource(gcryError));
        printf("%s\n",gcry_strerror(gcryError));
        return 1;
    }
    if(verbeux)printf("Vecteur d'initialisation : Ok.\n");
    free(InitVector);
    //-----END INIT VECTOR
  
    rewind(source);
  
    //-----------OBTENTION BUFFER DE LECTURE
    taille_buffer = get_buffer_cmd(info,&buffer_fichier, taille_fichier, verbeux);
      
    if(taille_buffer == 0){
        fclose(source);
        fclose(vidage);
        remove("temp");
        return 1;
    }
    //------------------END OBTENTION BUFFER
     
    //-------COPIE SOURCE -> VIDAGE
    copie_donnees_vidage_cmd(source, vidage, buffer_fichier, taille_buffer, taille_fichier, info, verbeux);
    fclose(source);
    free(buffer_fichier);
    //----END COPIE SOURCE -> VIDAGE
      
    //----------OBTENTION TAILLE EXTENSION
    fseek(vidage,taille_fichier-remplissage-1,SEEK_SET);
    if(fscanf(vidage,"%X",&taille_extension) != 1)
	{
		printf("Erreur : obtention taille extension.\n");
		fclose(vidage);
		remove("temp");
		free(buffer_fichier);
		return 1;
	}
    //------END OBTENTION TAILLE EXTENSION
      
    //------OBTENTION EXTENSION
    nomExtension = (char*)malloc(sizeof(char)*(taille_extension+1));
    if(nomExtension == NULL){
        printf("Erreur allocation memoire pour le nom de l'extension.\n");
        fclose(vidage);
        remove("temp");
    }
    fseek(vidage,-taille_extension-1,SEEK_CUR);
    if(fread(nomExtension,3,sizeof(char),vidage) == '\0')
	{
		printf("Erreur lecture du nom de l'extension.\n");
		fclose(vidage);
		remove("temp");
		free(buffer_fichier);
		return 1;
	}
    nomExtension[taille_extension]='\0';
      
    if(verbeux)printf("Nom extension : %s\n",nomExtension);
        
    //-------END OBTENTION EXTENSION
      
    //-------OBTENTION NOM DE FICHIER FINAL   
    if(get_nom(info->filename, &nomCible, nomExtension, taille_extension, info)){
        printf("Erreur d'obtention du nom de fichier (mémoire).\n");
        fclose(vidage);
        remove("temp");
        free(nomExtension);
        return 1;
    }
      
    free(nomExtension);
      
    if(verbeux) printf("Nom cible : %s\n",nomCible);
        
    //------END OBTENTION NOM DE FICHIER FINAL
      
    //-------OUVERTURE FICHIER FINAL
    cible = fopen(nomCible,"wb");
    if(cible == NULL)
    {
        printf("Echec création fichier\n");
        fclose(vidage);
        remove("temp");
        free(nomCible);
        return 1;
    }
    //-------END OUVERTURE FICHIER FINAL
      
    //-----CREATION BUFFER FINAL
    taille_fichier -= (remplissage+1+taille_extension);         
      
    taille_buffer = get_buffer_decrypt_cmd(info,&buffer_fichier, taille_fichier, verbeux);
      
    if(taille_buffer == 0){
        fclose(vidage);
        remove("temp");
        remove(nomCible);
        free(nomCible);
        return 1;
    }
    //------END CREATION BUFFER FINAL
      
    rewind(vidage);
    copie_donnees_final_cmd(vidage, cible, buffer_fichier, taille_buffer, taille_fichier, info, verbeux);
      
    printf("Dechiffrement termine.\n");
      
    fclose(vidage);
    fclose(cible);
    remove("temp");
    free(buffer_fichier);
    free(nomCible);
      
    if(info->Suppression)
    {
        if(verbeux)printf("Supression fichier source... ");
        remove(info->filename);
        if(verbeux)printf("Ok.\n");
    }

    free(info->filename);
      
    return 0;
}
   
int copie_donnees_vidage_cmd(FILE* source, FILE* cible, unsigned char* buffer_fichier,const long taille_buffer, const long taille_fichier, info_struct* info, bool verbeux)
{
    if(verbeux)printf("Copie donnees vers tampon...\n");   
    do{ 
        if(fread(buffer_fichier,1,taille_buffer,source) == '\0')
		{
			printf("Erreur.");
            return 1;
		}
        if(dechiffrement_cmd(buffer_fichier, taille_buffer, info, verbeux))
        {
            if(verbeux)printf("Abandon.");
            return 1;
        }
        fwrite(buffer_fichier,1,taille_buffer,cible);
      }while(ftell(source)+1 < taille_fichier);
         
    if(verbeux)printf("Copie Ok.\n");
    return 0;
}
   
int dechiffrement_cmd(unsigned char* buffer, long taille, info_struct* info, bool verbeux)
{
    gcry_error_t     gcryError;
    if(verbeux)printf("Dechiffrement... ");
    
    gcryError = gcry_cipher_decrypt(
        info->gcryCipherHd, // gcry_cipher_hd_t
        buffer,    // void *
        taille,    // size_t
        buffer,    // const void *
        taille);   // size_t
    if (gcryError)
    {
       printf("Erreur : dechiffrement.\n");
       printf("%s\n",gcry_strsource(gcryError));
       printf("%s\n",gcry_strerror(gcryError));
       return 1;
    }
    if(verbeux)printf("Ok.\n");
    return 0;
}

int copie_donnees_final_cmd(FILE* vidage, FILE* cible, unsigned char* buffer_fichier,const long taille_buffer,const long taille_fichier, info_struct* info, bool verbeux)
{
    if(verbeux)printf("Copie donnees depuis tampon ... ");
    do
    {
        if(fread(buffer_fichier,1,taille_buffer,vidage) == '\0')
		{
			printf("Erreur.\n");
			return 1;
		}
        fwrite(buffer_fichier,1,taille_buffer,cible);
    }while(ftell(vidage)+1 < taille_fichier);
      
    if(verbeux)printf("Ok.\n");
    return 0;
}
   
long get_buffer_decrypt_cmd(info_struct* info, unsigned char** buffer_fichier, const long taille_fichier, bool verbeux)
{
    if(verbeux)printf("Allocation memoire du buffer... ");
    long taille_buffer;
      
    taille_buffer = taille_fichier;
    *buffer_fichier = (unsigned char*)malloc(sizeof(unsigned char)*taille_buffer);
      
    if(*buffer_fichier != NULL && verbeux)printf("Ok\n");
    else{
        if(verbeux)printf("\nEchec. Tentative de diminution du buffer...\n");
        for(int i = 2; taille_buffer >=16; i++)
        {
            *buffer_fichier = (unsigned char*)malloc((taille_buffer/i)*sizeof(unsigned char));
            if(*buffer_fichier != NULL)
            {
               taille_buffer/=i;
               if(verbeux)printf("Ok\n");
               break;
            }
        }
      }
      if(verbeux)printf("Taille du buffer : %ld octets.\n", taille_buffer);
      if(*buffer_fichier == NULL)
      {
          if(verbeux)printf("Echec.\n");
          taille_buffer = 0;
      }
      else
         if(verbeux)printf("Allocation memoire Ok.\n");
      return taille_buffer;
}

//#endif