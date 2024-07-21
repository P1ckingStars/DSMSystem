#ifndef DEBUG_HPP
#define DEBUG_HPP


#include "../config/config.hpp"

#ifdef DEBUG 

#define DEBUG_STMT(stmt) stmt

#else

#define DEBUG_STMT(stmt) {}

#endif 

#endif
