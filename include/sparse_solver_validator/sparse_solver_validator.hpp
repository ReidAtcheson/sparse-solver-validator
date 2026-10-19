#pragma once


#include <array>
#include <cstdint>
#include <span>


namespace spvalid{

constexpr size_t seedbytes = 32;
using seed_t = std::array<seedbytes,uint8_t>;


class sparse_matrix_family_t{
  public:
    virtual
};

}
