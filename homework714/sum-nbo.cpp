#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>


int main(int argc, char* argv[]) {
    FILE* fp;
    uint32_t a=0;
    int sum=0;
    for(int i=1; i<argc; i++){
        fp = fopen(argv[i], "rb");
        if(fp==NULL){
            return -1;
        }
        fread(&a, sizeof(a), 1, fp);

        printf("(%d)%#010x", ntohl(a), ntohl(a));
        if(i<argc-1){
            printf(" +");
        }
        sum += ntohl(a);
        fclose(fp);
    }
    printf(" = (%d)%#010x\", sum, sum);
    return 0;

}

