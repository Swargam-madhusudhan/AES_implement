#include <wb.h>

#define wbCheck(stmt)                                                     \
  do {                                                                    \
    cudaError_t err = stmt;                                               \
    if (err != cudaSuccess) {                                             \
      wbLog(ERROR, "Failed to run stmt ", #stmt);                         \
      return -1;                                                          \
    }                                                                     \
  } while (0)


int main(int argc, char *argv[]) {
  wbArg_t arg;

  arg = wbArg_read(argc, argv); /* parse the input arguments */



  return 0;
}
