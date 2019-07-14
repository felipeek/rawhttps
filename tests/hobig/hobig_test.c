#include <stdio.h>
#include "hobig.h"
#include "../color.h"

/*

    UTILS

 */

// -1 if error | 0 if ok
int assert_equality_or_error(HoBigInt a, HoBigInt b, const char* funcname) {
    int err = 0;
    if(hobig_int_compare_signed(&a, &b) != 0) {
        printf("%sERROR%s: result mismatch (%s)\n", ColorRed, ColorReset, funcname);
        hobig_int_print(a);
        printf(" vs ");
        hobig_int_print(b);
        printf("\n");
        err = -1;
    }
    return err;
}

/*

    MODULAR EXPONENTIATION

 */

void test_hobig_mod_div() {
    HoBigInt expected_result = hobig_int_new_decimal("501248348680137206700200230754038114561517457980215131435328157614853152399325849997803765795869884711580198397290394448276053866068020527233596632592", 0);

    HoBigInt n = hobig_int_new_decimal("3498583697396045929521530877294658172929672028366635886651878300231171458955716406978353344141777843620007274024816664404408726333529655073078832344467478", 0);
    HoBigInt exp = hobig_int_new_decimal("4519843160463288062918580025639808781878043374837035832900655314965160862826437244686004073001718754779907361563410459626224219701665822904210168969401281", 0);
    HoBigInt m = hobig_int_new_decimal("10110484033288364727267901533905254561333242154983098415619163334591840653527959301220249016169719055550213534233664016249007347777310773318616485806202271", 0);

    HoBigInt res = hobig_int_mod_div(&n, &exp, &m);

    if(assert_equality_or_error(expected_result, res, __FUNCTION__) == 0) {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

/*

    DIVISION

 */

typedef struct {
    HoBigInt expected_r;
    HoBigInt expected_q;
    HoBigInt dividend;
    HoBigInt divisor;
} HoBigInt_Test_Div;

int run_test_hobig_div(HoBigInt_Test_Div tinstance) {
    HoBigInt_DivResult result = hobig_int_div(&tinstance.dividend, &tinstance.divisor);

    int err = 0;
    err |= assert_equality_or_error(tinstance.expected_q, result.quotient, __FUNCTION__);
    err |= assert_equality_or_error(tinstance.expected_r, result.remainder, __FUNCTION__);
    
    return err;
}

HoBigInt_Test_Div new_div_test_instance(const char* expected_q, const char* expected_r, const char* dividend, const char* divisor) {
    HoBigInt_Test_Div test = {0};
    test.expected_q = hobig_int_new_decimal(expected_q, 0);
    test.expected_r = hobig_int_new_decimal(expected_r, 0);
    test.dividend = hobig_int_new_decimal(dividend, 0);
    test.divisor = hobig_int_new_decimal(divisor, 0);
    return test;
}

void test_hobig_div() {
    HoBigInt_Test_Div test = new_div_test_instance(
        "195317441", "8708151304550333341762740528545",
        "1798549571982371273172984621940121021312", "9208340812094809129834192739487");
    
    if(run_test_hobig_div(test) == 0) {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

/*

    MULTIPLICATION

 */

typedef struct {
    HoBigInt expected;
    HoBigInt a;
    HoBigInt b;
} HoBigInt_Test_Mul;

int run_test_hobig_mul(HoBigInt_Test_Mul tinstance) {
    HoBigInt result = hobig_int_mul(&tinstance.a, &tinstance.b);
    return assert_equality_or_error(tinstance.expected, result, __FUNCTION__);
}

HoBigInt_Test_Mul new_mul_test_instance(const char* expected, const char* a, const char* b) {
    HoBigInt_Test_Mul test = {0};
    test.expected = hobig_int_new_decimal(expected, 0);
    test.a = hobig_int_new_decimal(a, 0);
    test.b = hobig_int_new_decimal(b, 0);
    return test;
}

void test_hobig_mul() {
    HoBigInt_Test_Mul test = new_mul_test_instance(
        "18051198169086036822819843655140436531410433782854856871560451173542701311154412887869687009517329402715803544138246881861632624062609852945489986752",
        "82091804098023950710758127088092183082103092183812398192084012904809821",
        "219890382084081290839218093821094070175712040921839089120830821983120312830912");
    
    if(run_test_hobig_mul(test) == 0) {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

/*

    ADDITION

 */

typedef struct {
    HoBigInt expected;
    HoBigInt a;
    HoBigInt b;
} HoBigInt_Test_Add;

HoBigInt_Test_Add new_add_test_instance(const char* expected, const char* a, const char* b) {
    HoBigInt_Test_Add test = {0};
    test.expected = hobig_int_new_decimal(expected, 0);
    test.a = hobig_int_new_decimal(a, 0);
    test.b = hobig_int_new_decimal(b, 0);
    return test;
}

int run_test_hobig_add(HoBigInt_Test_Add tinstance) {
    hobig_int_add(&tinstance.a, &tinstance.b);
    return assert_equality_or_error(tinstance.expected, tinstance.a, __FUNCTION__);
}

void test_hobig_add() {
    HoBigInt_Test_Add test = new_add_test_instance(
        "3987321794712749219592512238586159153920610416916105931547881089996155306124001777761665849212293355242911996625013",
        "3987321794712749128380210948091238059828501205984901230273802170301290391209389012890401927409172974012730712732910", 
        "91212301290494921094092109210931204701274078919694864914914612764871263921803120381230181283892103");
    
    if(run_test_hobig_add(test) == 0) {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

/*

    SUBTRACTION

 */

typedef struct {
    HoBigInt expected;
    HoBigInt a;
    HoBigInt b;
} HoBigInt_Test_Sub;

HoBigInt_Test_Sub new_sub_test_instance(const char* expected, const char* a, const char* b) {
    HoBigInt_Test_Sub test = {0};
    test.expected = hobig_int_new_decimal(expected, 0);
    test.a = hobig_int_new_decimal(a, 0);
    test.b = hobig_int_new_decimal(b, 0);
    return test;
}

int run_test_hobig_sub(HoBigInt_Test_Sub tinstance) {
    hobig_int_sub(&tinstance.a, &tinstance.b);
    return assert_equality_or_error(tinstance.expected, tinstance.a, __FUNCTION__);
}

void test_hobig_sub() {
    HoBigInt_Test_Sub test = new_sub_test_instance(
        "91212301290494921094092109210931204701274078919694864914914612764871263921803120381230181283892103",
        "3987321794712749219592512238586159153920610416916105931547881089996155306124001777761665849212293355242911996625013",
        "3987321794712749128380210948091238059828501205984901230273802170301290391209389012890401927409172974012730712732910");
    
    if(run_test_hobig_sub(test) == 0) {
        printf("%sOK%s: %s\n", ColorGreen, ColorReset, __FUNCTION__);
    }
}

int main() {
    test_hobig_sub();
    test_hobig_add();
    test_hobig_mul();
    test_hobig_div();
    test_hobig_mod_div();
    return 0;
}