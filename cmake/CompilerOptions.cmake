function(epn_set_compiler_options target)
  target_compile_options(${target} PRIVATE
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
    -Wconversion -Wshadow
    -fstack-protector-strong
    $<$<CONFIG:Debug>:-g -O0 -DEPN_DEBUG>
    $<$<CONFIG:Release>:-O3 -DNDEBUG -march=native>
    $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG>
  )
  # Security hardening
  target_compile_definitions(${target} PRIVATE
    _FORTIFY_SOURCE=2
  )
  target_link_options(${target} PRIVATE
    -Wl,-z,relro -Wl,-z,now
  )
  if(EPN_SANITIZE)
    target_compile_options(${target} PRIVATE
      -fsanitize=address,undefined
    )
    target_link_options(${target} PRIVATE
      -fsanitize=address,undefined
    )
  endif()
endfunction()
