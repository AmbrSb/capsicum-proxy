#include <tuple>


/* extern "C" */
/* int add(int a, int b) */
/* { */
/*     return a + b; */
/* } */

extern "C"
int add(std::tuple<int,int> tup)
{
    int a = std::get<0>(tup);
    int b = std::get<1>(tup);
    return a + b;
}

