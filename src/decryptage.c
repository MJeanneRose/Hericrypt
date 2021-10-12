//Construction : données, extension, taille extension, remplissage, nombre de bit de remplissage, initVector
//Dechiffrement : aes 256

#include "../include/decryptage.h"
   
#define progress_ajout 7.5
   
int Decrypt(void* data)
{
    // Do stuff.  This will be the first function called on the new thread.
    // When this function returns, the thread goes away.  See MSDN for more details.
    info_struct * info = (info_struct*)data;
    gtk_text_buffer_insert_at_cursor (info->buffer,"Ok\nOuverture du fichier à décrypter... ",-1);
     
    FILE* source;
     
    source=fopen(info->filename,"rb");
    if(source == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"échec.\n",-1);
        return 1;
    }
    modification_boutons(info, BOUTONS_DESACTIVER_TOUT);
    gtk_text_buffer_insert_at_cursor (info->buffer,"Ok\n",-1);
    
    barre_avancement(info, progress_ajout);
      
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
    barre_avancement(info, progress_ajout);

    //----OUVERTURE FICHIER DE VIDAGE
    vidage = fopen("temp","wb+");
    if(vidage == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Impossible d'ouvrir le fichier de vidage. Abandon\n",-1);
        fclose(source);
        free(InitVector);
        return 1;
    }
    //----END OUVERTURE FICHIER DE VIDAGE
    barre_avancement(info, progress_ajout);

    taille_fichier = get_taille_fichier(source)-17;//- (remplissage + initVector)

    //---------TAILLE REMPLISSAGE
    fseek(source,taille_fichier,SEEK_SET);
    if(fscanf(source,"%X",&remplissage) != 1)
	{
		gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : obtention valeur de remplissage.\n",-1);
		fclose(source);
		free(InitVector);
		return 1;
	}
    //-----END TAILLE REMPLISSAGE
    barre_avancement(info, progress_ajout);

    //---------INIT VECTOR
    fseek(source,taille_fichier+1,SEEK_SET);
    if(fread(InitVector,16,sizeof(unsigned char),source) == '\0')
	{
		gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : lecture du vecteur d'initialisation.\n",-1);
		fclose(source);
		free(InitVector);
        return 1;
	}
      
      
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
    free(InitVector);
    //-----END INIT VECTOR
    barre_avancement(info, progress_ajout);

    rewind(source);

    //-----------OBTENTION BUFFER DE LECTURE
    taille_buffer = get_buffer(info,&buffer_fichier, taille_fichier);
      
    if(taille_buffer == 0)
    {
        fclose(source);
        fclose(vidage);
        remove("temp");
        return 1;
    }
    //------------------END OBTENTION BUFFER
    barre_avancement(info, progress_ajout);

    //-------COPIE SOURCE -> VIDAGE
    copie_donnees_vidage(source, vidage, buffer_fichier, taille_buffer, taille_fichier, info);
    fclose(source);
    free(buffer_fichier);
    //----END COPIE SOURCE -> VIDAGE
    barre_avancement(info, progress_ajout);

    //----------OBTENTION TAILLE EXTENSION
    fseek(vidage,taille_fichier-remplissage-1,SEEK_SET);
    if(fscanf(vidage,"%X",&taille_extension) != 1)
	{
		gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : obtention taille extension.\n",-1);
		fclose(vidage);
		remove("temp");
		free(buffer_fichier);
		return 1;
	}
    //------END OBTENTION TAILLE EXTENSION

    //------OBTENTION EXTENSION
    nomExtension = (char*)malloc(sizeof(char)*(taille_extension+1));
    if(nomExtension == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur allocation mémoire pour le nom de l'extension.\n",-1);
        fclose(vidage);
        remove("temp");
    }
    fseek(vidage,-taille_extension-1,SEEK_CUR);
    if(fread(nomExtension,3,sizeof(char),vidage) == '\0')
	{
		gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur lecture du nom de l'extension.\n",-1);
		fclose(vidage);
		remove("temp");
		free(buffer_fichier);
		return 1;
	}
    nomExtension[taille_extension]='\0';

    gtk_text_buffer_insert_at_cursor (info->buffer,"Nom extension : ",-1);
    gtk_text_buffer_insert_at_cursor (info->buffer,nomExtension,-1);
    gtk_text_buffer_insert_at_cursor (info->buffer,".\n",-1);
    //-------END OBTENTION EXTENSION
    barre_avancement(info, progress_ajout);

    //-------OBTENTION NOM DE FICHIER FINAL   
    if(get_nom(info->filename, &nomCible, nomExtension, taille_extension, info))
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur d'obtention du nom de fichier (mémoire).\n",-1);
        fclose(vidage);
        remove("temp");
        free(nomExtension);
        return 1;
    }
      
    free(nomExtension);

    gtk_text_buffer_insert_at_cursor (info->buffer,"Nom cible : ",-1);
    gtk_text_buffer_insert_at_cursor (info->buffer,nomCible,-1);
    gtk_text_buffer_insert_at_cursor (info->buffer,".\n",-1);
    //------END OBTENTION NOM DE FICHIER FINAL

    //-------OUVERTURE FICHIER FINAL
    cible = fopen(nomCible,"wb");
    if(cible == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Echec création fichier\n",-1);
        fclose(vidage);
        remove("temp");
        free(nomCible);
        return 1;
    }
    //-------END OUVERTURE FICHIER FINAL
    barre_avancement(info, progress_ajout);

    //-----CREATION BUFFER FINAL
    taille_fichier -= (remplissage+1+taille_extension);         

    taille_buffer = get_buffer_decrypt(info,&buffer_fichier, taille_fichier);
      
    if(taille_buffer == 0)
    {
        fclose(vidage);
        remove("temp");
        remove(nomCible);
        free(nomCible);
        return 1;
    }
    //------END CREATION BUFFER FINAL
    barre_avancement(info, progress_ajout);

    rewind(vidage);
    copie_donnees_final(vidage, cible, buffer_fichier, taille_buffer, taille_fichier, info);

    fclose(vidage);
    fclose(cible);
    remove("temp");
    free(buffer_fichier);
    free(nomCible);

    if(info->Suppression)
    {
         remove(info->filename);
         info->Suppression = FALSE;
    }
      
    info->progress_bar_valeur = 1.0;
    gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR(info->progress_bar),info->progress_bar_valeur);

    g_free(info->filename);

    modification_boutons(info, BOUTONS_ACTIVER_SELECTION);
    return 0;
}
   
int get_nom(const char* chemin_complet, char** nom, const char* nomExtension, int taille_extension, info_struct* info)
{      
    int tailleChemin = strlen(chemin_complet);

    tailleChemin -= 10; //Suppression de '.hericrypt" de la taille du chemin

    *nom = malloc(sizeof(char)*(tailleChemin+taille_extension));//Ajout du '\0'
    if(*nom == NULL)
     return 1;

    int i;
    int j = 0;

    for(i = 0; i<=tailleChemin+taille_extension;i++)
    {
        if(i<=tailleChemin)
         nom[0][i] = chemin_complet[i]; 
        else
        {
           nom[0][i] = nomExtension[j];
           j++;
        }
    }
    nom[0][i] = '\0';
    return 0;
}
   
int copie_donnees_vidage(FILE* source, FILE* cible, unsigned char* buffer_fichier,const long taille_buffer, const long taille_fichier, info_struct* info)
{
    gtk_text_buffer_insert_at_cursor (info->buffer,"Copie données vers tampon ...\n",-1);   
    do
    { 
         if(fread(buffer_fichier,1,taille_buffer,source) == '\0')
		 {
			 gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur.\n",-1);
			 return 1;
		 }
         
         if(dechiffrement(buffer_fichier, taille_buffer, info))
         {
            gtk_text_buffer_insert_at_cursor (info->buffer,"Abandon.",-1);
            return 1;
         }
         fwrite(buffer_fichier,1,taille_buffer,cible);
    }while(ftell(source)+1 < taille_fichier);
     
    gtk_text_buffer_insert_at_cursor (info->buffer,"Copie Ok.\n",-1);
    return 0;
}
   
int dechiffrement(unsigned char* buffer, long taille, info_struct* info)
{
    gcry_error_t     gcryError;

    gtk_text_buffer_insert_at_cursor (info->buffer,"Déchiffrement... ",-1);

    gcryError = gcry_cipher_decrypt(
    info->gcryCipherHd, // gcry_cipher_hd_t
    buffer,    // void *
    taille,    // size_t
    buffer,    // const void *
    taille);   // size_t
    if (gcryError)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur : déchiffrement\n",-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strsource(gcryError),-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,gcry_strerror(gcryError),-1);
        gtk_text_buffer_insert_at_cursor (info->buffer,"\n",-1);
        return 1;
    }
    gtk_text_buffer_insert_at_cursor (info->buffer,"Ok.\n",-1);
    return 0;
}

int copie_donnees_final(FILE* vidage, FILE* cible, unsigned char* buffer_fichier,const long taille_buffer,const long taille_fichier, info_struct* info)
{
      
    gtk_text_buffer_insert_at_cursor (info->buffer,"Copie données depuis tampon ... ",-1);

    do
    {
         if(fread(buffer_fichier,1,taille_buffer,vidage) == '\0')
		 {
			 gtk_text_buffer_insert_at_cursor (info->buffer,"Erreur.\n",-1);
			 return 1;
		 }
         fwrite(buffer_fichier,1,taille_buffer,cible);
    }while(ftell(vidage)+1 < taille_fichier);

    gtk_text_buffer_insert_at_cursor (info->buffer,"Ok.\n",-1);
    return 0;
}
   
long get_buffer_decrypt(info_struct* info, unsigned char** buffer_fichier, const long taille_fichier)
{
    gtk_text_buffer_insert_at_cursor (info->buffer,"Allocation mémoire du buffer... ",-1);
    long taille_buffer;
    char temp[64];

    taille_buffer = taille_fichier;
    *buffer_fichier = (unsigned char*)malloc(sizeof(unsigned char)*taille_buffer);

    if(*buffer_fichier != NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Ok\n",-1);
    }
    else
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"\nEchec. Tentative de diminution du buffer...\n",-1);
        for(int i = 2; taille_buffer >=16; i++)
        {
            *buffer_fichier = (unsigned char*)malloc((taille_buffer/i)*sizeof(unsigned char));
            if(*buffer_fichier != NULL)
            {
                taille_buffer/=i;
                gtk_text_buffer_insert_at_cursor (info->buffer,"Ok\n",-1);
                break;
            }
        }
    }
    gtk_text_buffer_insert_at_cursor (info->buffer,"Taille du buffer : ",-1);
    sprintf(temp,"%ld",taille_buffer);
    gtk_text_buffer_insert_at_cursor (info->buffer,temp,-1);
    gtk_text_buffer_insert_at_cursor (info->buffer," octets\n",-1);
    if(*buffer_fichier == NULL)
    {
        gtk_text_buffer_insert_at_cursor (info->buffer,"Echec.\n",-1);
        taille_buffer = 0;
    }
    else
        gtk_text_buffer_insert_at_cursor (info->buffer,"Allocation mémoire Ok.\n",-1);
    return taille_buffer;
}
