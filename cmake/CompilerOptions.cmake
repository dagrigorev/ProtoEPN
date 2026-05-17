function(epn_set_compiler_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4
      /permissive-
      $<$<CONFIG:Debug>:/Od /Zi /DEPN_DEBUG>
      $<$<CONFIG:Release>:/O2 /DNDEBUG>
      $<$<CONFIG:RelWithDebInfo>:/O2 /Zi /DNDEBUG>
    )
  elseif(MINGW)
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic
      -Wno-unused-parameter
      -Wconversion -Wshadow
      $<$<CONFIG:Debug>:-g -O0 -DEPN_DEBUG>
      $<$<CONFIG:Release>:-O3 -DNDEBUG>
      $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG>
    )
  else()
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
  endif()
  if(EPN_SANITIZE)
    target_compile_options(${target} PRIVATE
      -fsanitize=address,undefined
    )
    target_link_options(${target} PRIVATE
      -fsanitize=address,undefined
    )
  endif()
endfunction()
