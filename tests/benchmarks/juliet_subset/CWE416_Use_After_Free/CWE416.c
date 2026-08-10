#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void CWE416_Use_After_Free__malloc_free_char_01_bad()
{
    char * data;
    data = NULL;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    memset(data, 'A', 100-1);
    data[100-1] = '\0';
    free(data);
    printf("Data: %s\n", data);
}
int main(int argc, char * argv[])
{
    CWE416_Use_After_Free__malloc_free_char_01_bad();
    return 0;
}
