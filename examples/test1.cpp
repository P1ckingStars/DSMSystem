
#include <cstdint>
#include <cstdlib>
#include <cstdlib> // For std::exit
#include <iostream>
#include <stdio.h>
#include <sys/mman.h>
#include <ucontext.h>

void dsm_main1(void *arg) {
  printf("---------------run user code now-------------\n");
  printf("complete!!!\n");
}

//   ucontext_t main_context, func_context;
//
//   void func() {
//       std::cout << "Inside func()" << std::endl;
//
//       // Switch back to the main context
//       swapcontext(&func_context, &main_context);
//
//       std::cout << "Back in func() after swap" << std::endl;
//
//       // Exit the program to avoid undefined behavior
//       std::exit(0);
//   }
//
//   void dsm_main1(void * arg) {
//       char * stack = new char[1024 * 64]; // Stack for the new context
//
//       // Get the current context as a template for func_context
//       getcontext(&func_context);
//
//       // Set up the new context
//       func_context.uc_stack.ss_sp = stack;
//       func_context.uc_stack.ss_size = sizeof(stack);
//       func_context.uc_link = nullptr; // Where to return after func()
//       finishes makecontext(&func_context, func, 0); // Set the function to
//       execute
//
//       std::cout << "Switching to func_context" << std::endl;
//
//       // Switch to the new context
//       swapcontext(&main_context, &func_context);
//
//       std::cout << "Back in main_context" << std::endl;
//   }
