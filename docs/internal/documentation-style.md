# Documentation style

Use the [GitHub Docs style guide](https://docs.github.com/en/contributing/style-guide-and-content-model/style-guide) as a supplemental editorial reference for repository documentation, agent instructions, and user-facing Markdown. Local requirements, schemas, templates, terminology, and generated-output contracts take precedence. GitHub-specific content models, Liquid syntax, product terminology, and list-marker conventions do not apply unless a local contract adopts them.

Apply these rules to new or substantively edited prose. Do not reflow unrelated text solely to make an existing file conform.

- Keep each Markdown prose paragraph, including prose in list items, on one source line. Separate paragraphs with one blank line. Use a hard break only when the rendered break carries meaning, never to limit source line length or create visual spacing.
- Use concise, direct, active language for the intended reader. Prefer one verifiable claim per sentence, and avoid idioms or region-specific slang.
- Use sentence case for headings, keep heading levels sequential, and put explanatory text between a heading and its first subheading.
- Use numbered lists for procedures, put prerequisites before the procedure, and give every step an action.
- Keep links necessary and descriptive. Link text identifies the destination or purpose; avoid labels such as "click here" and unnecessary duplicate links.
- Add a language identifier to fenced code blocks, omit shell prompts from copyable commands, and explain replaceable placeholders.
- Use alerts sparingly and match the alert level to the consequence. Images require meaningful alternative text, and videos or diagrams never replace required written information.
- Preserve deliberate line breaks in code blocks, tables, Mermaid diagrams, templates, generated fixtures, and other syntax-sensitive structures.
