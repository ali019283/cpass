#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gpgme.h>
int gpg(char *fpr, char *fp, int d){
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_key_t rkey = NULL;
    gpgme_check_version(NULL);
    gpgme_new(&ctx);
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
    gpgme_get_key(ctx, fpr, &rkey, 0);
    gpgme_data_t in;
    gpgme_data_t out;
    FILE *ifp;
    FILE *ofp;
    if (d){
        ifp = fopen("temp", "rb");
        ofp = fopen(fp, "wb");
        gpgme_data_new_from_stream(&in, ifp);
        gpgme_data_new_from_stream(&out, ofp);
        err = gpgme_op_encrypt(ctx, rkey, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
        if (err) {
            fprintf(stderr, "Error encrypting data: %s\n", gpgme_strerror(err));
            fclose(ifp);
            fclose(ofp);
            exit(1);
        }
        fclose(ifp);
        fclose(ofp);
    }else{
        ifp = fopen(fp, "rb");
        gpgme_data_new_from_stream(&in, ifp);
        gpgme_data_new(&out);
        gpgme_op_decrypt(ctx, in, out);
        if (err) {
            fprintf(stderr, "Error decrypting data: %s\n", gpgme_strerror(err));
            fclose(ifp);
            gpgme_data_release(in);
            gpgme_data_release(out);
            gpgme_release(ctx);
            exit(1);
        }
        ssize_t bytes;
        char buffer[4096];
        gpgme_data_seek(out, 0, SEEK_SET);
        while ((bytes = gpgme_data_read(out, buffer, sizeof(buffer))) > 0) {
            fwrite(buffer, 1, bytes, stdout);
        }
        printf("\n");
        fclose(ifp);
    }
    gpgme_key_unref(rkey);
    gpgme_data_release(in);
    gpgme_data_release(out);
    gpgme_release(ctx);
    return 0;
}
struct stat st = {0};
int main(int argc, char *argv[]){
    if (argc < 2){puts("err: too few arguments"); exit(1);}
    char *passpath = getenv("HOME");
    strcat(passpath, "/.password-store/");
    for (int i = 1; i < argc; i++){
        if (!strcmp(argv[i], "init")){
            if (i+1==argc){puts("Usage: pass init <gpg-id>");}
            if (i+1 == argc || !strcmp(argv[i+1], "insert") || !strcmp(argv[i+1], "show")){
                puts("Usage: cpass init <gpg-id>");
                return 1;
            }
            if (stat(passpath, &st) == -1){
                mkdir(passpath, 0700);
            }
            chdir(passpath); 
            FILE *fptr = fopen(".gpg-id", "w");
            fprintf(fptr, argv[i+1]);
            fclose(fptr);
            i++;
        }else if(!strcmp(argv[i], "insert") || !strcmp(argv[i], "-i")){
            if (i+1==argc){puts("Usage: cpass insert <pass-name>");}
            if (stat(passpath, &st) == -1){
                puts("Error: You must run:\n    cpass init your-gpg-id\nbefore you may use the password store.");
                return 1;
            }
            chdir(passpath);
            for (int n = i+1; n < argc; n++){
                if (!strcmp(argv[n], "show") || !strcmp(argv[n], "-s") || !strcmp(argv[n], "init")){
                    if(!strcmp(argv[i],"insert") || !strcmp(argv[i],"-i")){
                        puts("Usage: cpass insert <pass-name>");
                    }
                    i = n - 1;
                    break;
                }
                char passwd[128] = "\0";
                char h[128] = "\0";
                char gpgkey[128];
                //char *gpgf;
                if (access(argv[i+1], F_OK) == 0){
                    printf("a password already exists under said name %s, do you want to change the password?[y/N]: ", argv[i+1]);
                    scanf("%s", h);
                    if(!strcmp(h, "y")){
                        printf("changing password for %s\n", argv[i+1]);
                    }else{
                        continue;
                    }
                }
                printf("Enter password for %s: ", argv[i+1]);
                scanf("%s", passwd);
                printf("Retype password for %s: ", argv[i+1]);
                scanf("%s", h);
                if(strcmp(h, passwd)){
                    puts("Error: the entered passwords do not match.");
                    return 1;
                }
                FILE *fptr = fopen(".gpg-id", "r");
                fgets(gpgkey, 128, fptr);
                fptr = fopen("temp", "w");
                fprintf(fptr, "%s", passwd);
                fclose(fptr);
                gpg(gpgkey, argv[i+1], 1);
                i++;
            }
            remove("temp");
        }else if(!strcmp(argv[i], "show") || !strcmp(argv[i], "-s")){
            if (i+1==argc){puts("Usage: pass show <pass-name>");}
            if (i+1 == argc || !strcmp(argv[i+1], "init") || !strcmp(argv[i+1], "insert")){
                puts("Usage: cpass show <pass-name>");
                return 1;
            }
            for (int n = i+1; n < argc; n++){
                if (!strcmp(argv[n], "insert") || !strcmp(argv[n], "-i") || !strcmp(argv[n], "init")){
                    if(!strcmp(argv[i],"show") || !strcmp(argv[i],"-s")){
                        puts("Usage: cpass show <pass-name>");
                    }
                    i = n - 1;
                    break;
                }
                char password[128];
                if (stat(passpath, &st) == -1){
                    puts(passpath);
                    puts("Error: You must run:\n    cpass init your-gpg-id\nbefore you may use the password store.");
                    return 1;
                }
                chdir(passpath);
                if (!access(argv[i+1], F_OK) == 0){
                    printf("no password exists under said name %s, run 'cpass insert %s' to create\n", argv[i+1], argv[i+1]);
                    return 1;
                }
                gpg(NULL, argv[i+1], 0);
                i++;
            }
        }
    }
}