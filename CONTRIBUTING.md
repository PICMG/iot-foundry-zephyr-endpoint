# Documentation and Comments

Use Doxygen-style comments for public APIs and modules. Keep descriptions concise and document parameters, return values, and any side-effects.

## Commenting style

- File header: each C source should start with a block comment describing the file name (@file),
  purpose, author/license (@author), and the full license text. Use a C-style block with two
  leading asterisks so it is easily picked up by documentation tools, for example:

  /**
   * @file filename.c
   *   ...
   */

- File header: each C header files should follow the same format as C files.

- Function-level comments: use Doxygen-like block comments immediately above functions.
  Start with a one-line summary and follow with a concise paragraph if more detail is
  required. Document if parameters are expected, document parameters using the `@param` 
  tag. If a return value is supplied, document with the `@return` tag.
  Example:

  /**
   * @brief This function does something.
   *
   * This is a more detailed description of how the function works from 
   * a user perspective.
   *
   * @param param1 - This paramter is ....
   * @return uint8_t Returns 1 if the valid, 0 otherwise.
   */

- Function-level comments: do not provide funciton-level comments for function declarations
  whether in C files or header files.  If multiple declarations exist that are logically grouped
  together (such as forward references) it is acceptable to have a single line commnet that 
  explains the purpose of the declarations (but not full function-level commenting).
  
- Inline comments: use `/* ... */` or `//` for short explanations within functions. Prefer
  brief sentences that explain the "why" rather than the "what" (the code shows the
  what). Keep them short and place them on their own line when explaining a block of code.

- Tag usage: prefer these tags when applicable: `@file`, `@brief`, `@param`, `@return`,
  and `@author`. Keep tags lowercase as in the examples above.

- Empty lines: separate the block comment from the function signature with a single blank line.
 - Empty lines: do not place a blank line between a function's Doxygen block
   comment and its function definition; the block comment should be immediately
   above the function signature.

- Don't repeat obvious information: avoid comments that restate the code; instead document
  intent, invariants, assumptions, side-effects, and reasons for non-obvious decisions.

- Licensing and attribution: include copyright/license information in the file header when
  appropriate.

## C Style Rules (project preferences)

- Avoid `(void)` in parameter lists; prefer an empty parameter list for C functions when
  appropriate.
- Use explicit types (`uint8_t`, `uint16_t`, etc.) from `<stdint.h>` in public interfaces.
- Keep functions small and focused; prefer clear naming over clever abbreviations.
- Keep internal symbols `static` unless they are part of the public API.

## Tests

Unit tests are under `tests/`.  Your code must build properly and pass all tests to be acceptable for submission.


## Commit messages and PRs

Keep commit messages short and descriptive. For larger changes, include a brief summary and rationale in the commit body.

## Questions or exceptions

If you need to deviate from these rules for a specific, justified reason, add a comment to the PR explaining why and request reviewer approval.

Thanks for contributing — consistent style keeps the code review process fast and focused.
