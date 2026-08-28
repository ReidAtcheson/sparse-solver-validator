#include <cstdlib>
#include <random>

int main() {
  std::philox4x32 engine;
  for (int i = 0; i < 9'999; ++i) {
    (void)engine();
  }

  return engine() == 1'955'073'260 ? EXIT_SUCCESS : EXIT_FAILURE;
}
