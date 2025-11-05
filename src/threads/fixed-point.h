/*
* 17. 14 fixed point representation
* Sign: 1bit
* Integer: 16bits
* Fraction: 14bits
*/

typedef int fixed_t;

#define F (1 << 14)

#define INT_TO_FIXED(n) ((n) * F)

#define FIXED_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + F / 2) / F : ((x) - F / 2) / F)
#define FIXED_TO_INT_TRUNC(x) ((x) / F)

#define ADD_FIXED(x, y) ((x) + (y))

#define SUB_FIXED(x, y) ((x) - (y))

#define ADD_MIXED(x, n) ((x) + INT_TO_FIXED(n))

#define SUB_MIXED(x, n) ((x) - INT_TO_FIXED(n)) 

#define MULT_FIXED(x, y) ((fixed_t)(((int64_t)(x)) * (y) / F))

#define MULT_INT(x, n) ((x) * (n))

#define DIV_FIXED(x, y) ((fixed_t)(((int64_t)(x)) * F / (y)))   

#define DIV_INT(x, n) ((x) / (n))