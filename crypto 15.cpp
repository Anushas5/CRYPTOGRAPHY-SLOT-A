#include <stdio.h>
#include <string.h>
void printTheString(char Str[], int K){
   char ptext[5][K+1];
   int fre[26] = { 0 }; 
   int freSorted[26]; 
   int Used[26] = { 0 }; 
   for (int i = 0; i < K; i++) {
      if (Str[i] != ' ') {
         fre[Str[i] - 'A']++;
      }
   } 
   for (int i = 0; i < 26; i++) {
      freSorted[i] = fre[i];
   } 
   char T[] = "ETAOINSHRDLCUMWFGYPBVKJXQZ"; 
   for (int i = 0; i < 26; i++) {
      for (int j = i + 1; j < 26; j++) {
         if (freSorted[j] > freSorted[i]) {
            int temp = freSorted[i];
            freSorted[i] = freSorted[j];
            freSorted[j] = temp;
         }
      }
   } 
   for (int i = 0; i < 5; i++) {
      int ch = -1; 
      for (int m = 0; m < 26; m++) { 
         if (freSorted[i] == fre[m] && Used[m] == 0) {
            Used[m] = 1;
            ch = m;
            break;
         }
      }
      if (ch == -1)
         break; 
      int x = T[i] - 'A'; 
      x = x - ch; 
      char cur[K+1]; 
      for (int T = 0; T < K; T++) { 
         if (Str[T] == ' ') {
            cur[T] = ' ';
            continue;
         } 
         int y = Str[T] - 'A';
         y =y+x; 
         if (y < 0)
            y =y+ 26;
         if (y > 25)
            y -=26; 
         cur[T] = 'A' + y;        
      }
      cur[K] = '\0';
      printf("%s\n", cur);
   }
}
int main(){
   char Str[] = "SGHR HR SGD BNCD";
   int K = strlen(Str);
   printTheString(Str, K);
   return 0;
}
