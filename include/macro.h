/* some useful macros */

#ifndef ISABELLE
#define EXCLUDE(X) X
#else
#define EXCLUDE(X)
#endif

#define xstr(s) str(s)
#define str(s) #s

#ifndef NDEBUG
#define ASSERT(X)                                                              \
  {                                                                            \
    if (!(X)) {                                                                \
      out_string("\nAssertion failed: '" xstr(X) "'\n\n");                            \
      exit(-1);                                                                \
    }                                                                          \
  }
#else
void assert(bool);
#define ASSERT(X) assert(X);
#endif

#define UNUSED(x) (void)(x)
