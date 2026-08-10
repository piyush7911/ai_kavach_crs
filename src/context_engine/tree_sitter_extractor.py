"""
AI Kavach CRS — Tree-sitter Context Extractor
Extracts vulnerable functions and their type dependencies from C/C++ source files
using AST-aware parsing. This prevents LLM context window exhaustion.
"""

import logging
from pathlib import Path
from typing import Optional

import tree_sitter_c as tsc
import tree_sitter_cpp as tscpp
from tree_sitter import Language, Parser, Node

logger = logging.getLogger(__name__)

# Initialize language grammars
C_LANGUAGE = Language(tsc.language())
CPP_LANGUAGE = Language(tscpp.language())


class ContextExtractor:
    """
    AST-aware code context extractor using Tree-sitter.
    Extracts the vulnerable function + related type definitions to provide
    focused, compilable context to LLM agents.
    """

    def __init__(self):
        self.c_parser = Parser(C_LANGUAGE)
        self.cpp_parser = Parser(CPP_LANGUAGE)

    def extract_context(
        self,
        file_path: str,
        line_number: int,
        language: str = "c",
        max_context_lines: int = 500,
    ) -> dict:
        """
        Extract the function containing the given line number,
        along with related struct/typedef/enum definitions.

        Args:
            file_path: Path to the source file.
            line_number: The line number of the vulnerability (1-indexed).
            language: "c" or "cpp".
            max_context_lines: Maximum total lines to return.

        Returns:
            dict with keys:
                "function_name": str
                "function_code": str
                "type_definitions": str  (related structs, typedefs, enums)
                "includes": str  (include directives)
                "full_context": str  (everything combined, ready for LLM)
                "file_path": str
                "start_line": int
                "end_line": int
                "extraction_method": "tree-sitter" | "fallback"
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")

        source_bytes = path.read_bytes()
        source_text = source_bytes.decode("utf-8", errors="replace")

        # Try Tree-sitter parsing first
        try:
            parser = self.cpp_parser if language == "cpp" else self.c_parser
            tree = parser.parse(source_bytes)
            result = self._extract_with_tree_sitter(
                tree.root_node, source_bytes, source_text, line_number, file_path
            )
            if result:
                result["extraction_method"] = "tree-sitter"
                # Trim if too long
                if len(result["full_context"].splitlines()) > max_context_lines:
                    result = self._trim_context(result, max_context_lines)
                return result
        except Exception as e:
            logger.warning(f"Tree-sitter parsing failed: {e}. Falling back to regex extraction.")

        # Fallback: regex-based extraction
        result = self._extract_fallback(source_text, line_number, file_path)
        result["extraction_method"] = "fallback"
        return result

    def _extract_with_tree_sitter(
        self,
        root: Node,
        source_bytes: bytes,
        source_text: str,
        line_number: int,
        file_path: str,
    ) -> Optional[dict]:
        """Extract function and type context using Tree-sitter AST."""

        # Find the function containing the target line (0-indexed internally)
        target_line = line_number - 1
        func_node = self._find_enclosing_function(root, target_line)

        if not func_node:
            logger.warning(f"No function found at line {line_number}")
            return None

        # Extract function name
        func_name = self._get_function_name(func_node)

        # Extract function code
        func_code = source_bytes[func_node.start_byte:func_node.end_byte].decode(
            "utf-8", errors="replace"
        )

        # Extract type definitions (structs, typedefs, enums) referenced in the function
        type_names = self._find_type_references(func_node, source_bytes)
        type_defs = self._extract_type_definitions(root, source_bytes, type_names)

        # Extract include directives
        includes = self._extract_includes(root, source_bytes)

        # Build full context
        parts = []
        if includes:
            parts.append(f"// === Include Directives ===\n{includes}")
        if type_defs:
            parts.append(f"// === Type Definitions ===\n{type_defs}")
        parts.append(f"// === Vulnerable Function (line {line_number}) ===\n{func_code}")

        full_context = "\n\n".join(parts)

        return {
            "function_name": func_name,
            "function_code": func_code,
            "type_definitions": type_defs,
            "includes": includes,
            "full_context": full_context,
            "file_path": file_path,
            "start_line": func_node.start_point[0] + 1,
            "end_line": func_node.end_point[0] + 1,
        }

    def find_function_span(
        self, file_path: str, function_name: str, language: str = "c"
    ) -> Optional[tuple[int, int]]:
        """
        Byte range [start, end) of a named function definition in a file.

        This backs the whole-function patch format: instead of asking the model
        to emit a unified diff whose context lines must match byte-for-byte, we
        let it return the corrected function and splice it in by AST range.
        Diff-formatting mistakes then cannot cause a valid fix to be rejected.

        Returns None if the function is not found (ambiguity is impossible —
        C forbids two definitions of the same name in a translation unit).
        """
        source_bytes = Path(file_path).read_bytes()
        parser = self.cpp_parser if language == "cpp" else self.c_parser
        tree = parser.parse(source_bytes)

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "function_definition":
                if self._get_function_name(node) == function_name:
                    return node.start_byte, node.end_byte
            stack.extend(node.children)
        return None

    def replace_function(
        self, file_path: str, function_name: str, new_source: str, language: str = "c"
    ) -> bool:
        """
        Replace a function's definition in-place with `new_source`.
        Returns False (leaving the file untouched) if the function is not found.
        """
        span = self.find_function_span(file_path, function_name, language)
        if span is None:
            return False

        start, end = span
        data = Path(file_path).read_bytes()
        replacement = new_source.rstrip().encode("utf-8")
        Path(file_path).write_bytes(data[:start] + replacement + data[end:])
        return True

    def _find_enclosing_function(self, node: Node, target_line: int) -> Optional[Node]:
        """Find the function_definition node containing the target line."""
        func_types = {"function_definition", "function_declarator"}

        # Check if this node is a function definition containing our line
        if node.type == "function_definition":
            if node.start_point[0] <= target_line <= node.end_point[0]:
                return node

        # Recurse into children
        best = None
        for child in node.children:
            if child.start_point[0] <= target_line <= child.end_point[0]:
                result = self._find_enclosing_function(child, target_line)
                if result and result.type == "function_definition":
                    best = result

        # If we didn't find one in children, check if any direct child is a function
        if best is None and node.type == "function_definition":
            if node.start_point[0] <= target_line <= node.end_point[0]:
                return node

        return best

    def _get_function_name(self, func_node: Node) -> str:
        """
        Extract the function name from a function_definition node.

        The declarator is not always a direct child: a pointer-returning
        function (`Node* create_node(int)`) nests the function_declarator inside
        a pointer_declarator, and `char (*f(void))[10]` nests it deeper still.
        Descend through those wrappers rather than only checking direct
        children, otherwise such functions are reported as "unknown".
        """
        declarator = self._find_function_declarator(func_node)
        if declarator is not None:
            for child in declarator.children:
                if child.type in ("identifier", "field_identifier", "qualified_identifier"):
                    return child.text.decode("utf-8") if child.text else "unknown"
                # C++ methods: `Class::method` lives under a nested declarator.
                if child.type == "scoped_identifier" and child.text:
                    return child.text.decode("utf-8")
        return "unknown"

    def _find_function_declarator(self, node: Node, depth: int = 0) -> Optional[Node]:
        """Depth-first search for the function_declarator inside a definition."""
        if depth > 8:
            return None
        for child in node.children:
            if child.type == "function_declarator":
                return child
            if child.type in (
                "pointer_declarator", "parenthesized_declarator",
                "array_declarator", "reference_declarator", "declarator",
            ):
                found = self._find_function_declarator(child, depth + 1)
                if found is not None:
                    return found
        return None

    def _find_identifier(self, node: Node) -> str:
        """Recursively find the first identifier in a node."""
        if node.type == "identifier":
            return node.text.decode("utf-8") if node.text else "unknown"
        for child in node.children:
            result = self._find_identifier(child)
            if result != "unknown":
                return result
        return "unknown"

    def _find_type_references(self, func_node: Node, source_bytes: bytes) -> set:
        """Find all type names referenced in a function (struct, enum, typedef names)."""
        type_names = set()
        self._collect_type_identifiers(func_node, source_bytes, type_names)
        return type_names

    def _collect_type_identifiers(self, node: Node, source_bytes: bytes, type_names: set):
        """Recursively collect type identifiers from a node."""
        # Look for type_identifier nodes (used in declarations, casts, etc.)
        if node.type == "type_identifier":
            name = source_bytes[node.start_byte:node.end_byte].decode("utf-8")
            type_names.add(name)

        # Also look for struct specifiers referencing a name
        if node.type in ("struct_specifier", "enum_specifier", "union_specifier"):
            for child in node.children:
                if child.type == "type_identifier" or child.type == "identifier":
                    name = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
                    type_names.add(name)

        for child in node.children:
            self._collect_type_identifiers(child, source_bytes, type_names)

    def _extract_type_definitions(
        self, root: Node, source_bytes: bytes, type_names: set
    ) -> str:
        """Extract struct/typedef/enum definitions that match the referenced type names."""
        if not type_names:
            return ""

        definitions = []
        for child in root.children:
            if child.type in (
                "struct_specifier",
                "enum_specifier",
                "type_definition",
                "declaration",
            ):
                text = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
                # Check if any referenced type name appears in this definition
                for name in type_names:
                    if name in text:
                        definitions.append(text)
                        break

        return "\n\n".join(definitions)

    def _extract_includes(self, root: Node, source_bytes: bytes) -> str:
        """Extract all #include directives from the file."""
        includes = []
        for child in root.children:
            if child.type == "preproc_include":
                text = source_bytes[child.start_byte:child.end_byte].decode("utf-8")
                includes.append(text)
        return "\n".join(includes)

    def _extract_fallback(
        self, source_text: str, line_number: int, file_path: str, window: int = 100
    ) -> dict:
        """
        Fallback extraction: grab ±100 lines around the target line.
        Used when Tree-sitter can't parse the file (e.g., heavy macro usage).
        """
        lines = source_text.splitlines()
        start = max(0, line_number - 1 - window)
        end = min(len(lines), line_number - 1 + window)
        extracted = "\n".join(lines[start:end])

        return {
            "function_name": f"unknown (fallback at line {line_number})",
            "function_code": extracted,
            "type_definitions": "",
            "includes": "",
            "full_context": f"// === Fallback Extraction ±{window} lines around line {line_number} ===\n{extracted}",
            "file_path": file_path,
            "start_line": start + 1,
            "end_line": end,
        }

    @staticmethod
    def _trim_context(result: dict, max_lines: int) -> dict:
        """Trim context to fit within max_lines while preserving function code."""
        lines = result["full_context"].splitlines()
        if len(lines) <= max_lines:
            return result

        # Prioritize: function code first, then types, then includes
        func_lines = result["function_code"].splitlines()
        remaining = max_lines - len(func_lines) - 5  # 5 lines for section headers

        type_lines = result["type_definitions"].splitlines()[:max(remaining // 2, 20)]
        include_lines = result["includes"].splitlines()[:10]

        parts = []
        if include_lines:
            parts.append("// === Include Directives (trimmed) ===\n" + "\n".join(include_lines))
        if type_lines:
            parts.append("// === Type Definitions (trimmed) ===\n" + "\n".join(type_lines))
        parts.append(f"// === Vulnerable Function ===\n{result['function_code']}")

        result["full_context"] = "\n\n".join(parts)
        return result
