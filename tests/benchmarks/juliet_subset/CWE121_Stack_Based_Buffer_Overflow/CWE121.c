#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SRC_STR "0123456789abcdef0123456789abcde"
typedef struct _charVoid
{
    char charFirst[16];
    void * voidSecond;
    void * voidThird;
} charVoid;
void CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad()
{
    {
        charVoid structCharVoid;
        structCharVoid.voidSecond = (void *)SRC_STR;
        printf("Data: %s\n", (char *)structCharVoid.voidSecond);
        memcpy(structCharVoid.charFirst, SRC_STR, sizeof(charVoid));
        structCharVoid.charFirst[(sizeof(structCharVoid.charFirst)/sizeof(char))-1] = '\0'; 
        printf("Data: %s\n", (char *)structCharVoid.voidSecond);
    }
}
int main(int argc, char * argv[])
{
    CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad();
    return 0;
}
