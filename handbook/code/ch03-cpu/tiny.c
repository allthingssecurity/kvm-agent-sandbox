/* tiny.c: three small functions to read as machine code. */

/* noinline keeps each function separate, so we can see the calls. */
__attribute__((noinline)) int add(int a, int b)
{
    return a + b;
}

__attribute__((noinline)) int sum_to(int n)
{
    int s = 0;
    for (int i = 1; i <= n; i++)
        s = add(s, i);
    return s;
}

int main(void)
{
    return sum_to(4);   /* 1 + 2 + 3 + 4: the exit status is 10 */
}
