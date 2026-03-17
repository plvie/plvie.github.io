#undef _GLIBCXX_DEBUG                // disable run-time bound checking, etc
#pragma GCC optimize("Ofast,inline") // Ofast = O3,fast-math,ect

#include <stdio.h>
#include <stdlib.h>
#include <math.h>  //only for logl
#include <time.h>
#include <fcntl.h>

// macro faster than function call
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define ABS(a) (((a)<0)?(-a):(a))
#define find_first_multiple(a,p) ((a % p == 0) ? a : a + p - a % p)
#define ilog2(x) (63 - __builtin_clzll(x)) // count leading zeros (clz) for x, then subtract from 63 to get ilog2(x)

unsigned long long ipow(unsigned long long base, unsigned long long exp) {
    unsigned long long result = 1;
    while (exp) {
        if (exp & 1){
            result *= base;
        }
        exp >>= 1;
        base *= base;
    }
    return result;
}


unsigned long long isqrt(unsigned long long n) { //cohen method
    unsigned long long x = n;
    unsigned long long y = (x + n/x) >> 1;
    while (y < x) {
        x = y;
        y = (x + n/x) >> 1;
    }
    return x;
}

unsigned long long icbrt(unsigned long long n) { //newton method
    unsigned long long x = n;
    unsigned long long y = (2*x + n/(x*x)) / 3;
    while (y < x) {
        x = y;
        y = (2*x + n/(x*x)) / 3;
    }
    return x;
}

char* cribler(unsigned long long b){
    char* tab = (char*) calloc(b+1, sizeof(char));
    tab[0] = 1;
    tab[1] = 1;
    for(unsigned long long i = 2; i <= isqrt(b); i++){
        if(tab[i] == 0){
            for(unsigned long long j = i*i; j <= b; j+=i){
                tab[j] = 1;
            }
        }
    }
    return tab;
}

unsigned long long* prime(unsigned long long b, unsigned long long* len_array){ // reduit taille array (approx x/ln(x))
    char* tab = cribler(b);
    unsigned long long len = 0;
    for(unsigned long long i = 0; i <= b; i++){
        if(tab[i] == 0){
            len++;
        }
    }
    unsigned long long* prime_array = (unsigned long long*) malloc(len * sizeof(unsigned long long)); 
    unsigned long long j = 0;
    for(unsigned long long i = 0; i <= b; i++){
        if(tab[i] == 0){
            prime_array[j] = i;
            j++;
        }
    }
    free(tab);
    *len_array = len;
    return prime_array;
}

void mobius(unsigned long long a, unsigned long long b, unsigned long long* prime_array, unsigned long long len_prime_array, long long* tab){
    if (a > b){
        return;
    }
    for (unsigned long long i = 0; i < b-a ; tab[i++] = 1);
    for (unsigned long long k = 0; k < len_prime_array; k++){
        unsigned long long p = prime_array[k];
        unsigned long long p_square = p*p;
        if (p_square > b){
            break;
        }
        for (unsigned long long i = find_first_multiple(a,p_square); i < b; tab[i-a] = 0, i+=p_square);
        for (unsigned long long j = find_first_multiple(a,p); j < b; j+=p){
            tab[j-a] = tab[j-a] * -p;
        }  
    }
        for (unsigned long long m = a; m < b; m++){
            if (tab[m-a] != 0) {
            if (ABS(tab[m-a]) < m ){
                tab[m-a] = tab[m-a] * -1;
            }
            if (tab[m-a] > 0){
                tab[m-a] = 1;
            }
            else{
                tab[m-a] = -1;
            }
            }
        }
}

unsigned long long compute_u(unsigned long long x){
    unsigned long long u = icbrt(x * logl(logl(x)) * logl(logl(x))); //exactly equal to powl(x, 1.0/3.0) * powl(logl(logl(x)), 2.0/3.0);
    //unsigned long long u = icbrt(x * ilog2(ilog2(x)) * ilog2(ilog2(x)));
    return u;
}

long long* LBlock(unsigned long long L, unsigned long long k, long long* L_array, unsigned long long * prime_array, unsigned long long len_prime_array, long long* tablemobius){
    mobius(k*L+1, (k+1)*L+1, prime_array, len_prime_array, tablemobius);
    L_array[0] = L_array[L-1] + tablemobius[0];
    for (unsigned long long i = 1; i < L; i++){
        L_array[i] = tablemobius[i] + L_array[i-1];
    }
    return L_array;
}

unsigned long long S1_S2_Block(long long* L_array, unsigned long long L, unsigned long long u, unsigned long long x, unsigned long long* prime_array, unsigned long long len_prime_array, long long* mobius_array_u, long long* mobius_array_use_for_L){
    long long S1 = 0;
    long long* mertens_array_u = (long long*) calloc(u, sizeof(long long));
    unsigned long long* sqrt_x_m = (unsigned long long*) malloc(u * sizeof(unsigned long long));
    unsigned long long* x_m = (unsigned long long*) malloc(u * sizeof(unsigned long long));
    unsigned long long m;
    for (m = 1; m <= u; m++){ //precompute sqrt(x/m) and x/m
        sqrt_x_m[m-1]= isqrt(x/m);
        x_m[m-1] = x/m;
    }
    //printf("S1 Block\n");
    L_array[L-1] = 0;
    unsigned long long k_bis;
    unsigned long long secondterm;

    long long S2 = 0;
    unsigned long long sqrt_x = isqrt(x);

    unsigned long long n; 
    for (unsigned long long k = 0; k <= x/(u*L); k++){
        L_array = LBlock(L, k, L_array, prime_array, len_prime_array, mobius_array_use_for_L);
        for (m = 1; m <= u; m++){
            for (n = MIN(sqrt_x_m[m-1],x_m[m-1]/(1+k*L)); n > MAX(u/m, x_m[m-1]/(1+(k+1)*L)); n--){
                    mertens_array_u[m-1] += L_array[(x_m[m-1]/n) -L*k - 1];
            }
    }
    
    //printf("S1 Block finish : %lld of %lld\n",k+1, (x/(u*L))+1);
    if (1+k*L > sqrt_x){ 
            continue;
    } else{
        for (k_bis = MAX(1, 1+k*L); k_bis <= MIN(sqrt_x, 1+(k+1)*L); k_bis++){
            secondterm = 0;
        for (m = 1; m <= MIN(u, x/(k_bis*k_bis)); m++){
            secondterm += mobius_array_u[m-1] * (x_m[m-1]/k_bis - MAX(x_m[m-1]/(k_bis+1), sqrt_x_m[m-1]));
        }
        S2 += L_array[k_bis - k*L - 1] * secondterm;
        }
        //printf("S2 Block finish : %lld of %lld\n",k+1, (sqrt_x/L)+1);
    }
    }
    free(sqrt_x_m);
    free(x_m);
    for (m = 1; m <= u; m++){
        S1 += mobius_array_u[m-1] * mertens_array_u[m-1];
    }
    free(mertens_array_u);
    // printf("S1 = %lld\n", S1);
    // printf("S2 = %lld\n", S2);
    return S1+S2;
}

int main(){
    time_t x_time_debut = time(NULL);
    clock_t x_debut=clock();
    unsigned long long x = ipow(10, 12);
    //printf("x = %lld\n", x);
    unsigned long long u = compute_u(x);
    //printf("u = %lld\n", u);

    unsigned long long len_prime_array;
    unsigned long long* prime_array = prime(isqrt(x /u) , &len_prime_array);
    // L and malloc
    int Lfactor = 256;
    unsigned long long L = Lfactor * u;
    long long* L_array = (long long*) malloc(L*sizeof(long long));
    long long* mobius_array_use_for_L = malloc(L * sizeof(long long));
    long long* mobius_array_u = malloc(u * sizeof(long long));

    //Start of compute 
    //printf("L = %lld\n", L);
    mobius(1, u+1, prime_array, len_prime_array, mobius_array_u);
    //Start of S1 and S2
    clock_t S_debut=clock();
    long long S1_S2 = S1_S2_Block(L_array, L, u, x, prime_array, len_prime_array, mobius_array_u, mobius_array_use_for_L);
    clock_t S_fin = clock();
    unsigned long long millis = (S_fin -  S_debut) * 1000 / CLOCKS_PER_SEC;
    printf( "Finished S1 and S2 in %lld ms\n", millis ); 
    //Finish
    long long mertens_u = 0;
    for (unsigned long long i = 0; i < u; i++){
        mertens_u += mobius_array_u[i];
    }
    clock_t x_fin=clock();
    time_t x_time_fin = time(NULL);
    long long mertens_x = mertens_u - S1_S2;
    printf("mertens_x = %lld\n", mertens_x);
    millis = (x_fin -  x_debut) * 1000 / CLOCKS_PER_SEC;
    printf( "Finished (cpu time) in %lld ms\n", millis );
    printf( "Finished in %ld s\n", x_time_fin - x_time_debut );
    free(L_array);
    free(prime_array);
    free(mobius_array_u);
    free(mobius_array_use_for_L);
    return 0;
}