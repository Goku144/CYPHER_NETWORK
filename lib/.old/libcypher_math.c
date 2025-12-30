//libcypher_math.c
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <gmp.h>
#include <cypher.h>

typedef struct
{
    mpz_t coeff;
    size_t deg;
} CY_POLY;

void cy_poly_init(CY_POLY *pol)
{
    mpz_init(pol->coeff);
    pol->deg = 0;
}

void cy_poly_inits(CY_POLY *pol, ...)
{
    va_list ap;
    va_start(ap, pol);
    for (CY_POLY *p = pol; p != NULL; p = va_arg(ap, CY_POLY *))
    {
        mpz_init(p->coeff);
        cy_poly_set_str("0", p);
    }
    va_end(ap);
}

void cy_poly_set(const CY_POLY pola, CY_POLY *pol)
{
    mpz_set(pol->coeff, pola.coeff);
    pol->deg = pola.deg;
}

void cy_poly_init_str(const char *coeff, CY_POLY *pol)
{
    mpz_init(pol->coeff);
    cy_poly_set_str(coeff, pol);
}

void cy_poly_inits_str(const char *coeff, CY_POLY *pol, ...)
{
    va_list ap;
    va_start(ap, pol);
    for (CY_POLY *p = pol; p != NULL; p = va_arg(ap, CY_POLY *))
    {
        mpz_init(p->coeff);
        cy_poly_set_str(coeff, p);
    }
    va_end(ap);
}

void cy_poly_set_str(const char *coeff, CY_POLY *pol)
{
    if (mpz_set_str(pol->coeff, coeff, 2) != 0)
        cy_state("cy_poly_set_str: invalid binary string", -1);
    cy_poly_deg(pol);
}

void cy_poly_deg(CY_POLY *pol)
{
    pol->deg = mpz_sizeinbase(pol->coeff, 2) - 1;
}

void cy_poly_swap(CY_POLY *pola, CY_POLY *polb)
{
    mpz_swap(pola->coeff, polb->coeff);
    size_t tmpdeg = pola->deg;
    pola->deg = polb->deg;
    polb->deg = tmpdeg;
}

void cy_poly_add(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol)
{
    mpz_xor(pol->coeff, pola.coeff, polb.coeff);
    cy_poly_deg(pol);
}

void cy_poly_sub(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol)
{
    cy_poly_add(pola, polb, pol);
}

void cy_poly_mul(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol)
{
    cy_poly_set_str("0", pol);
    mpz_t tmpol; mpz_init(tmpol);
    for (size_t i = 0; i <= pola.deg; i++)
    {
        if(mpz_tstbit(pola.coeff, i)) 
        {
            mpz_set_ui(tmpol, 0);
            mpz_mul_2exp(tmpol, polb.coeff, i);
            mpz_xor(pol->coeff, pol->coeff, tmpol);
        }
    }
    cy_poly_deg(pol);
    mpz_clear(tmpol);
}

void cy_poly_div(const CY_POLY pola, const CY_POLY polb, CY_POLY *polq, CY_POLY *polm)
{
    cy_poly_set_str("0", polq);
    cy_poly_set(pola, polm);

    CY_POLY tmpol, m, a; 
    cy_poly_inits(&tmpol, &m, &a, NULL);

    while (mpz_sgn(polm->coeff) != 0 && polm->deg >= polb.deg)
    {
        cy_poly_set(*polm, &a);
        mpz_set_ui(tmpol.coeff, 0);
        tmpol.deg = polm->deg - polb.deg;
        mpz_setbit(tmpol.coeff, tmpol.deg);
        mpz_setbit(polq->coeff, tmpol.deg);
        cy_poly_mul(tmpol, polb, &tmpol);
        cy_poly_add(tmpol, a, polm);
    }
    cy_poly_deg(polq);
    cy_poly_clears(&tmpol, &m, &a, NULL);
}

void cy_poly_divq(const CY_POLY pola, const CY_POLY polb, CY_POLY *polq)
{
    CY_POLY tmpolm; cy_poly_init(&tmpolm);
    cy_poly_div(pola, polb, polq, &tmpolm);
    cy_poly_clear(&tmpolm);
}

void cy_poly_mod(const CY_POLY pola, const CY_POLY polb, CY_POLY *polm)
{
    CY_POLY tmpolq; cy_poly_init(&tmpolq);
    cy_poly_div(pola, polb, &tmpolq, polm);
    cy_poly_clear(&tmpolq);
}

void cy_poly_gcd(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol)
{
    if(mpz_sgn(pola.coeff) == 0) {cy_poly_set(polb, pol); return;}
    if(mpz_sgn(polb.coeff) == 0) {cy_poly_set(pola, pol); return;}
    CY_POLY tmpola, tmpolb, tmpolm; 
    cy_poly_inits(&tmpola, &tmpolb, &tmpolm, NULL);

    cy_poly_set(pola, &tmpola); 
    cy_poly_set(polb, &tmpolb);
    while (mpz_sgn(tmpolb.coeff) != 0)
    {
        cy_poly_mod(tmpola, tmpolb, &tmpolm);
        cy_poly_set(tmpolb, &tmpola);
        cy_poly_set(tmpolm, &tmpolb);
    }
    cy_poly_set(tmpola, pol);
    cy_poly_clears(&tmpola, &tmpolb, &tmpolm, NULL);
}

void cy_poly_field_mul(const CY_POLY pola, const CY_POLY polb, const CY_POLY polm, CY_POLY *pol)
{
    CY_POLY tmp; cy_poly_init(&tmp);
    cy_poly_mul(pola, polb, &tmp);
    cy_poly_mod(tmp, polm, pol);
    cy_poly_clear(&tmp);
}

void cy_poly_field_inv(const CY_POLY pola, const CY_POLY polm, CY_POLY *pol)
{
    if(!mpz_sgn(pola.coeff)) {cy_poly_set_str("0", pol); return;}
    CY_POLY g; cy_poly_init(&g);
    cy_poly_gcd(pola, polm, &g);
    if (mpz_cmp_ui(g.coeff, 1) != 0) 
    {
        cy_poly_clear(&g);
        cy_state("cy_poly_field_inv: pola and polm are not relatively prime!", -1);
    }
    cy_poly_clear(&g);

    CY_POLY tmpola, tmpolm, __x, _x, x, q, r, mod, tmp; 
    cy_poly_inits(&tmpola, &tmpolm, &__x, &_x, &x, &q, &r, &mod, &tmp, NULL);
    cy_poly_set(pola, &tmpola);
    cy_poly_set(polm, &tmpolm);
    cy_poly_set(polm, &mod);
    cy_poly_set_str("1", &__x);
    cy_poly_set_str("0", &_x);

    while (mpz_sgn(tmpolm.coeff))
    {
        cy_poly_mod(tmpola, tmpolm, &r);
        cy_poly_divq(tmpola, tmpolm, &q); 
        cy_poly_mul(q, _x, &tmp); 
        cy_poly_add(tmp, __x, &x);
        cy_poly_swap(&__x, &_x); 
        cy_poly_swap(&_x, &x);
        cy_poly_swap(&tmpola, &tmpolm);
        cy_poly_swap(&tmpolm, &r);
    }

    cy_poly_mod(__x, mod, &r); 
    cy_poly_add(r, mod, &tmp); 
    cy_poly_mod(tmp, mod, pol);
    cy_poly_clears(&tmpola, &tmpolm, &__x, &_x, &x, &q, &r, &mod, &tmp, NULL);
}

void cy_poly_print(const CY_POLY pol)
{
    size_t first = 1;
    for (size_t i = pol.deg; __UINT64_MAX__ > i; i--)
    {
        if(mpz_tstbit(pol.coeff, i))
        {
            if(!first) printf(" + ");
            if(i > 1) printf("X(%zu)", i);
            if(i == 1) printf("X");
            if(i == 0) printf("1");
            first = 0;
        }
    }
    if (mpz_sgn(pol.coeff) == 0) printf("0");
}

void cy_poly_clear(CY_POLY *pol)
{
    mpz_clear(pol->coeff);
    pol->deg = 0;
}

void cy_poly_clears(CY_POLY *pol, ...)
{
    va_list ap;
    va_start(ap, pol);
    for (CY_POLY *p = pol; p != NULL; p = va_arg(ap, CY_POLY *))
    {
        mpz_clear(p->coeff);
        p->deg = 0;
    }
    va_end(ap);
}

// void cy_state(const char *str, int _errnum);

// void cy_poly_init(CY_POLY *pol);

// void cy_poly_inits(CY_POLY *pol, ...);

// void cy_poly_set(const CY_POLY pola, CY_POLY *pol);

// void cy_poly_init_str(const char *coeff, CY_POLY *pol);

// void cy_poly_inits_str(const char *coeff, CY_POLY *pol, ...);

// void cy_poly_set_str(const char *coeff, CY_POLY *pol);

// void cy_poly_deg(CY_POLY *pol);

// void cy_poly_swap(CY_POLY *pola, CY_POLY *polb);

// void cy_poly_add(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol);

// void cy_poly_sub(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol);

// void cy_poly_mul(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol);

// void cy_poly_div(const CY_POLY pola, const CY_POLY polb, CY_POLY *polq, CY_POLY *polm);

// void cy_poly_divq(const CY_POLY pola, const CY_POLY polb, CY_POLY *polq);

// void cy_poly_mod(const CY_POLY pola, const CY_POLY polb, CY_POLY *polm);

// void cy_poly_gcd(const CY_POLY pola, const CY_POLY polb, CY_POLY *pol);

// void cy_poly_field_inv(const CY_POLY pola, const CY_POLY polm, CY_POLY *pol);

// void cy_poly_field_mul(const CY_POLY pola, const CY_POLY polb, const CY_POLY polm, CY_POLY *pol);

// void cy_poly_print(const CY_POLY pol);

// void cy_poly_clear(CY_POLY *pol);

// void cy_poly_clears(CY_POLY *pol, ...);

// void xtime(uint8_t *x);