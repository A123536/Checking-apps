"""Build an atomic, offline SQLite source index. No source files are modified."""
import argparse
import ast
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import uuid
import sys
from board_preprocessor import specialize

from tree_sitter import Language, Parser
import tree_sitter_c

BOARD_MACROS = {'ATP': 'IS_5728_MCP', 'IPB': 'IS_570_IPB', 'OPB': 'IS_570_OPB', 'SPB': 'IS_570_SIG'}

SCHEMA = """
PRAGMA user_version=1;
PRAGMA foreign_keys=ON;
CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE files(id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL, sha256 TEXT NOT NULL,
 encoding TEXT NOT NULL, content TEXT NOT NULL, has_errors INTEGER NOT NULL);
CREATE TABLE functions(id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files,
 name TEXT NOT NULL, signature TEXT NOT NULL, line INTEGER NOT NULL, end_line INTEGER NOT NULL,
 is_static INTEGER NOT NULL, condition TEXT NOT NULL, has_errors INTEGER NOT NULL);
CREATE TABLE calls(id INTEGER PRIMARY KEY, function_id INTEGER NOT NULL REFERENCES functions,
 expression TEXT NOT NULL, name TEXT NOT NULL, line INTEGER NOT NULL, column_no INTEGER NOT NULL,
 kind TEXT NOT NULL, condition TEXT NOT NULL, has_errors INTEGER NOT NULL);
CREATE TABLE edges(call_id INTEGER NOT NULL REFERENCES calls, target_id INTEGER NOT NULL REFERENCES functions,
 resolution TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY(call_id,target_id));
CREATE TABLE macros(id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files,
 name TEXT NOT NULL, expression TEXT NOT NULL, line INTEGER NOT NULL, function_like INTEGER NOT NULL,
 condition TEXT NOT NULL);
CREATE TABLE log_sites(id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL REFERENCES calls,
 code INTEGER, code_expression TEXT NOT NULL, data_expression TEXT NOT NULL,
 length_expression TEXT NOT NULL);
CREATE TABLE bindings(id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES files,
 line INTEGER NOT NULL, slot TEXT NOT NULL, target_id INTEGER NOT NULL REFERENCES functions,
 condition TEXT NOT NULL);
CREATE TABLE diagnostics(id INTEGER PRIMARY KEY, file_id INTEGER REFERENCES files,
 line INTEGER NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL);
CREATE INDEX functions_name ON functions(name);
CREATE INDEX calls_function ON calls(function_id);
CREATE INDEX edges_target ON edges(target_id);
CREATE INDEX logs_code ON log_sites(code);
CREATE VIEW call_details AS SELECT c.*, f.name AS caller, f.file_id, s.path
 FROM calls c JOIN functions f ON f.id=c.function_id JOIN files s ON s.id=f.file_id;
"""


def walk(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def text(node):
    return node.text.decode('utf-8') if node is not None else ''


def field(node, name):
    return node.child_by_field_name(name) if node is not None else None


def declared_name(node):
    if node is None:
        return ''
    if node.type in ('identifier', 'field_identifier', 'type_identifier'):
        return text(node)
    return declared_name(field(node, 'declarator')) or next(
        (declared_name(child) for child in node.named_children
         if child.type not in ('parameter_list', 'initializer_list') and declared_name(child)), '')


def base_type(node):
    return re.sub(r'\b(struct|const|volatile)\b|[\s*]', '', text(node))


def function_declaration(declarator):
    name = declared_name(declarator)
    identifier = next((node for node in walk(declarator)
                       if node.type == 'identifier' and text(node) == name), None)
    parent = identifier.parent if identifier else None
    while parent is not None:
        if parent.type in ('pointer_declarator', 'array_declarator'):
            return False
        if parent.type == 'function_declarator':
            return True
        if parent == declarator:
            break
        parent = parent.parent
    return False


def conditions(lines):
    """Retain branch expressions. Macro configuration is deliberately not guessed."""
    result, stack = {}, []
    in_comment = False
    for number, line in enumerate(lines, 1):
        # Preserve line numbering while excluding directives in block comments.
        clean = ''
        position = 0
        for match in re.finditer(r'/\*|\*/', line):
            if not in_comment:
                clean += line[position:match.start()]
            in_comment = match.group() == '/*'
            position = match.end()
        if not in_comment:
            clean += line[position:]
        match = re.match(r'^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)', clean)
        if match:
            directive, expression = match.groups()
            expression = expression.split('//')[0].strip()
            if directive in ('if', 'ifdef', 'ifndef'):
                if directive == 'ifdef':
                    expression = f'defined({expression})'
                if directive == 'ifndef':
                    expression = f'!defined({expression})'
                stack.append([expression, [expression]])
            elif directive in ('elif', 'else') and stack:
                previous = ' || '.join(f'({item})' for item in stack[-1][1])
                stack[-1][0] = f'!({previous})'
                if directive == 'elif':
                    stack[-1][0] += f' && ({expression})'
                    stack[-1][1].append(expression)
            elif directive == 'endif' and stack:
                stack.pop()
        result[number] = ' && '.join(f'({entry[0]})' for entry in stack)
    return result


def constant(expression, definitions, active=None):
    """Evaluate only safe integer expressions with unambiguous object-like macros."""
    active = set() if active is None else active
    expression = re.sub(r'/\*.*?\*/|//[^\n]*', '', expression, flags=re.S).strip()
    expression = re.sub(r'\b(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]+\b', r'\1', expression)
    try:
        node = ast.parse(expression, mode='eval').body
    except (SyntaxError, ValueError):
        return None

    def evaluate(item):
        if isinstance(item, ast.Constant) and type(item.value) is int:
            return item.value
        if isinstance(item, ast.Name) and item.id not in active:
            values = definitions.get(item.id, set())
            if len(values) == 1:
                return constant(next(iter(values)), definitions, active | {item.id})
        if isinstance(item, ast.UnaryOp):
            value = evaluate(item.operand)
            if value is not None:
                return {ast.UAdd: lambda: value, ast.USub: lambda: -value,
                        ast.Invert: lambda: ~value}.get(type(item.op), lambda: None)()
        if isinstance(item, ast.BinOp):
            left, right = evaluate(item.left), evaluate(item.right)
            if left is None or right is None:
                return None
            operations = {ast.Add: lambda: left + right, ast.Sub: lambda: left - right,
                          ast.Mult: lambda: left * right, ast.BitOr: lambda: left | right,
                          ast.BitAnd: lambda: left & right, ast.BitXor: lambda: left ^ right,
                          ast.LShift: lambda: left << right if 0 <= right < 64 else None,
                          ast.RShift: lambda: left >> right if 0 <= right < 64 else None}
            return operations.get(type(item.op), lambda: None)()
        return None
    try:
        value = evaluate(node)
        return value if value is not None and -(2**63) <= value < 2**63 else None
    except (ValueError, OverflowError, RecursionError):
        return None


class Index:
    def __init__(self, database, root, cancel_path=None, profile=None):
        self.db = database
        self.root = root
        self.units = []
        self.functions = []
        self.by_name = defaultdict(list)
        self.structs = {}
        self.definitions = defaultdict(set)
        self.macro_functions = set()
        self.slots = defaultdict(list)
        self.global_types = {}
        self.pointer_types = set()
        self.known_prototypes = set()
        self.headers = defaultdict(list)
        self.type_names = set()
        self.cancel_path = cancel_path
        self.profile = profile
        self.unknown_configuration = set()
        self.missing_configuration_includes = set()

    def check_cancelled(self):
        if self.cancel_path and Path(self.cancel_path).exists():
            raise ValueError('Build cancelled')

    def diagnostic(self, unit, line, kind, message):
        self.db.execute('INSERT INTO diagnostics(file_id,line,kind,message) VALUES(?,?,?,?)',
                        (unit['id'], line, kind, message))

    def load(self):
        parser = Parser(Language(tree_sitter_c.language()))
        paths = sorted(p for p in self.root.rglob('*') if p.suffix.lower() in ('.c', '.h') and p.is_file())
        if not paths:
            raise ValueError('No C/H source files found')
        known_headers = {p.name.casefold() for p in paths}
        if self.profile and self.profile.get('_configuration_path'): known_headers.add('project_or_board_ptcl.h')
        header_paths = defaultdict(list)
        source_cache = {}
        source_hash_cache = {}
        if self.profile and self.profile.get('_configuration_path'):
            source_cache[self.profile['_configuration_path']] = self.profile['_configuration_content']
            source_hash_cache.update(self.profile['_configuration_dependencies'])
        for path in paths: header_paths[path.name.casefold()].append(path)
        def load_include(name, source):
            if self.profile and name in self.profile.get('ignore_includes', []): return None
            candidates = [Path(source).parent / name, self.root / name]
            config = self.profile.get('_configuration_path') if self.profile else None
            existing = Path(config) if config and Path(name).name.casefold() == 'project_or_board_ptcl.h' else next((p for p in candidates if p.is_file()), None)
            if existing is None:
                matches = header_paths.get(Path(name).name.casefold(), [])
                existing = matches[0] if len(matches) == 1 else None
            if existing is None:
                if config and Path(source).parent == Path(config).parent:
                    self.missing_configuration_includes.add(name)
                    self.profile['_has_missing_configuration_include'] = True
                return None
            identity = str(existing.resolve())
            if identity not in source_cache:
                raw = existing.read_bytes()
                try: value = raw.decode('utf-8-sig')
                except UnicodeDecodeError: value = raw.decode('gb18030', errors='replace')
                source_cache[identity] = re.sub(r'\r+\n|\r', '\n', value)
                source_hash_cache[identity] = hashlib.sha256(raw).hexdigest()
            if config and Path(source).parent == Path(config).parent:
                self.profile['_configuration_dependencies'][identity] = source_hash_cache[identity]
            return identity, source_cache[identity]
        for path in paths:
            self.check_cancelled()
            raw = path.read_bytes()
            encoding = None
            for candidate in ('utf-8-sig', 'gb18030'):
                try:
                    content = raw.decode(candidate)
                    encoding = candidate
                    break
                except UnicodeDecodeError:
                    pass
            if encoding is None:
                content, encoding = raw.decode('gb18030', errors='replace'), 'gb18030-replacement'
            content = re.sub(r'\r+\n|\r', '\n', content)
            original_conditions = conditions(content.splitlines())
            unresolved = []
            if self.profile:
                content, unresolved, unknown = specialize(content, self.profile, load_include, str(path), include_stack={str(path.resolve())})
                self.unknown_configuration.update(unknown)
                for name, value in self.profile.get('_resolved_defines', {}).items(): self.definitions[name].add(value)
            tree = parser.parse(content.encode('utf-8'))
            relative = path.relative_to(self.root).as_posix()
            cursor = self.db.execute('INSERT INTO files(path,sha256,encoding,content,has_errors) VALUES(?,?,?,?,?)',
                                     (relative, hashlib.sha256(raw).hexdigest(), encoding, content, tree.root_node.has_error))
            unit = dict(id=cursor.lastrowid, path=relative, tree=tree, content=content,
                        conditions=original_conditions, globals={}, includes=[])
            self.units.append(unit)
            self.headers[Path(relative).name.casefold()].append(unit)
            for line, expression in unresolved:
                self.diagnostic(unit, line, 'unresolved_configuration', expression)
            if encoding.endswith('replacement'):
                self.diagnostic(unit, 1, 'encoding', 'Invalid byte sequences replaced in stored snapshot')
            for node in walk(tree.root_node):
                line = node.start_point.row + 1
                if node.type == 'type_identifier':
                    self.type_names.add(text(node))
                if node.type == 'ERROR' or node.is_missing:
                    self.diagnostic(unit, line, 'parse_error', text(node)[:180] or 'Missing token')
                if node.type == 'preproc_include':
                    header = text(field(node, 'path')).strip('"<>')
                    unit['includes'].append(header.replace('\\', '/'))
                    if Path(header.replace('\\', '/')).name.casefold() not in known_headers:
                        self.diagnostic(unit, line, 'external_include', header)
                if node.type in ('preproc_def', 'preproc_function_def'):
                    name, expression = text(field(node, 'name')), text(field(node, 'value'))
                    function_like = node.type == 'preproc_function_def'
                    self.db.execute('INSERT INTO macros(file_id,name,expression,line,function_like,condition) VALUES(?,?,?,?,?,?)',
                                    (unit['id'], name, expression, line, function_like, unit['conditions'].get(line, '')))
                    if function_like:
                        self.macro_functions.add(name)
                    else:
                        self.definitions[name].add(expression)
                if node.type == 'type_definition':
                    declarator = field(node, 'declarator')
                    if declarator and any(n.type == 'function_declarator' for n in walk(declarator)):
                        self.pointer_types.add(declared_name(declarator))
                    structure = field(node, 'type')
                    if structure and structure.type == 'struct_specifier':
                        body = field(structure, 'body')
                        members = []
                        for member in body.named_children if body else []:
                            if member.type == 'field_declaration':
                                for decl in member.children_by_field_name('declarator'):
                                    members.append((declared_name(decl), base_type(field(member, 'type'))))
                        if members:
                            self.structs[declared_name(declarator)] = members
                            tag = text(field(structure, 'name'))
                            if tag:
                                self.structs[tag] = members
            print(f'Indexed syntax {len(self.units)}/{len(paths)} {relative}', flush=True)

    def collect_functions(self):
        for unit in self.units:
            self.check_cancelled()
            for node in walk(unit['tree'].root_node):
                if node.type == 'function_definition':
                    name = declared_name(field(node, 'declarator'))
                    body = field(node, 'body')
                    if not name or body is None:
                        continue
                    signature = unit['content'].encode('utf-8')[node.start_byte:body.start_byte].decode('utf-8').strip()
                    line = node.start_point.row + 1
                    cursor = self.db.execute('INSERT INTO functions(file_id,name,signature,line,end_line,is_static,condition,has_errors) VALUES(?,?,?,?,?,?,?,?)',
                                            (unit['id'], name, signature, line, node.end_point.row + 1,
                                             bool(re.search(r'\bstatic\b', signature)), unit['conditions'].get(line, ''), node.has_error))
                    function = dict(id=cursor.lastrowid, unit=unit, name=name, node=node, body=body,
                                    static=bool(re.search(r'\bstatic\b', signature)), types={}, assignments=defaultdict(list), returns=[])
                    self.functions.append(function)
                    self.by_name[name].append(function)
                elif node.type == 'declaration':
                    for decl in node.children_by_field_name('declarator'):
                        if function_declaration(decl):
                            self.known_prototypes.add(declared_name(decl))
            # Global variables belong to this source unit, including duplicate static names.
            for node in walk(unit['tree'].root_node):
                if node.type != 'declaration':
                    continue
                parent = node.parent
                inside_function = False
                while parent:
                    if parent.type == 'function_definition':
                        inside_function = True
                        break
                    parent = parent.parent
                if not inside_function:
                    self.add_types(node, unit['globals'])
        for function in self.functions:
            function['types'].update(function['unit']['globals'])
            for node in walk(function['node']):
                if node.type in ('parameter_declaration', 'declaration'):
                    self.add_types(node, function['types'])
                if node.type == 'assignment_expression':
                    function['assignments'][text(field(node, 'left'))].append(field(node, 'right'))
                if node.type == 'init_declarator':
                    function['assignments'][declared_name(field(node, 'declarator'))].append(field(node, 'value'))
                if node.type == 'return_statement' and node.named_children:
                    function['returns'].append(node.named_children[0])

    @staticmethod
    def add_types(node, destination):
        for decl in node.children_by_field_name('declarator'):
            if node.type == 'parameter_declaration' or not function_declaration(decl):
                destination[declared_name(decl)] = base_type(field(node, 'type'))

    def resolve_name(self, name, unit):
        definitions = self.by_name.get(name, [])
        local = [fn for fn in definitions if fn['unit'] is unit]
        if local:
            return local
        # Header-static functions are candidates only if reachable through local includes.
        visible = self.header_closure(unit)
        return [fn for fn in definitions if not fn['static'] or fn['unit']['path'] in visible]

    def header_closure(self, unit):
        if 'headers' in unit:
            return unit['headers']
        found, pending = set(), [unit]
        while pending:
            current = pending.pop()
            for name in current['includes']:
                for header in self.headers.get(Path(name).name.casefold(), []):
                    if header['path'] not in found:
                        found.add(header['path'])
                        pending.append(header)
        unit['headers'] = found
        return found

    def expression_type(self, node, types):
        if node is None:
            return ''
        if node.type == 'identifier':
            return types.get(text(node), '')
        if node.type == 'field_expression':
            structure = self.expression_type(field(node, 'argument'), types)
            return dict(self.structs.get(structure, [])).get(text(field(node, 'field')), '')
        if node.type == 'subscript_expression':
            return self.expression_type(field(node, 'argument'), types)
        if node.type in ('pointer_expression', 'parenthesized_expression') and node.named_children:
            return self.expression_type(node.named_children[-1], types)
        return ''

    def slot_key(self, node, types):
        if node is not None and node.type == 'field_expression':
            structure = self.expression_type(field(node, 'argument'), types)
            if structure in self.structs:
                return structure + '.' + text(field(node, 'field'))
        return ''

    def collect_bindings(self):
        for unit in self.units:
            self.check_cancelled()
            for node in walk(unit['tree'].root_node):
                if node.type != 'declaration':
                    continue
                structure = base_type(field(node, 'type'))
                members = self.structs.get(structure)
                if not members:
                    continue
                for decl in node.children_by_field_name('declarator'):
                    value = field(decl, 'value')
                    if value is None or value.type != 'initializer_list':
                        continue
                    is_array = any(n.type == 'array_declarator' for n in walk(field(decl, 'declarator')))
                    rows = [item for item in value.named_children if item.type != 'comment'] if is_array else [value]
                    for row in rows:
                        if row.type != 'initializer_list':
                            continue
                        items = [item for item in row.named_children if item.type != 'comment']
                        for position, item in enumerate(items):
                            member = members[position][0] if position < len(members) else ''
                            if item.type == 'initializer_pair':
                                designator = next((n for n in walk(item) if n.type == 'field_identifier'), None)
                                member = text(designator)
                                item = field(item, 'value')
                            for reference in walk(item):
                                if reference.type != 'identifier':
                                    continue
                                for target in self.resolve_name(text(reference), unit):
                                    slot = structure + '.' + member
                                    evidence = f"{unit['path']}:{reference.start_point.row + 1} initializer {slot}"
                                    self.slots[slot].append((target, evidence))
                                    self.db.execute('INSERT INTO bindings(file_id,line,slot,target_id,condition) VALUES(?,?,?,?,?)',
                                                    (unit['id'], reference.start_point.row + 1, slot, target['id'],
                                                     unit['conditions'].get(reference.start_point.row + 1, '')))

    def pointer_targets(self, node, function, seen=None):
        if node is None:
            return []
        seen = set() if seen is None else seen
        key = (function['id'], text(node))
        if key in seen:
            return []
        seen = seen | {key}
        slot = self.slot_key(node, function['types'])
        if slot:
            return self.slots.get(slot, [])
        if node.type == 'identifier':
            name = text(node)
            if name not in function['types']:
                return [(target, 'Function address ' + name) for target in self.resolve_name(name, function['unit'])]
            return [target for value in function['assignments'].get(name, [])
                    for target in self.pointer_targets(value, function, seen)]
        if node.type == 'call_expression':
            name = text(field(node, 'function'))
            return [(target, f"return of {name}; {evidence}")
                    for helper in self.resolve_name(name, function['unit'])
                    for value in helper['returns']
                    for target, evidence in self.pointer_targets(value, helper, seen)]
        if node.type in ('parenthesized_expression', 'pointer_expression', 'cast_expression') and node.named_children:
            return self.pointer_targets(node.named_children[-1], function, seen)
        return []

    def collect_calls(self):
        for function in self.functions:
            self.check_cancelled()
            unit = function['unit']
            for node in walk(function['body']):
                if node.type != 'call_expression':
                    continue
                callee = field(node, 'function')
                name, line = text(callee), node.start_point.row + 1
                # C's grammar can represent (ExternalTypedef)(value) as a call.
                # Only discard these when the parenthesized name is a known type.
                if callee.type == 'parenthesized_expression' and name.strip('() \t') in self.type_names:
                    continue
                indirect = callee.type != 'identifier' or name in function['types']
                kind = 'indirect' if indirect else 'direct'
                targets = []
                if indirect:
                    targets = self.pointer_targets(callee, function)
                elif name in self.macro_functions:
                    kind = 'macro'
                else:
                    targets = [(target, 'Name and file scope; preprocessing not evaluated')
                               for target in self.resolve_name(name, unit)]
                    if not targets:
                        kind = 'external' if name in self.known_prototypes else 'unresolved'
                cursor = self.db.execute('INSERT INTO calls(function_id,expression,name,line,column_no,kind,condition,has_errors) VALUES(?,?,?,?,?,?,?,?)',
                                        (function['id'], text(node), name, line, node.start_point.column + 1,
                                         kind, unit['conditions'].get(line, ''), node.has_error))
                call_id = cursor.lastrowid
                for target, evidence in targets:
                    resolution = 'candidate' if indirect or len(targets) > 1 else 'source_direct'
                    self.db.execute('INSERT OR IGNORE INTO edges VALUES(?,?,?,?)',
                                    (call_id, target['id'], resolution, evidence))
                arguments = field(node, 'arguments')
                args = arguments.named_children if arguments else []
                if name in ('DarkLogPrint', 'SpecialDarkLogPrint') and len(args) >= 4:
                    code_expr = text(args[2])
                    self.db.execute('INSERT INTO log_sites(call_id,code,code_expression,data_expression,length_expression) VALUES(?,?,?,?,?)',
                                    (call_id, constant(code_expr, self.definitions), code_expr, text(args[1]), text(args[3])))
                elif name == 'AbnorDarkLogPrint' and len(args) >= 2:
                    expression = text(args[0])
                    values = self.definitions.get(expression, set())
                    # These compound-literal macros put the numeric log type in the first member.
                    codes = {match.group(1) for value in values
                             if (match := re.search(r'\{\s*([A-Za-z_]\w*|0[xX][\da-fA-F]+)\s*,', value))}
                    code = constant(next(iter(codes)), self.definitions) if len(codes) == 1 else None
                    self.db.execute('INSERT INTO log_sites(call_id,code,code_expression,data_expression,length_expression) VALUES(?,?,?,?,?)',
                                    (call_id, code, expression, text(args[1]), ''))


def read_profiles(path=None):
    profiles_path = Path(path) if path else Path(__file__).with_name('board_profiles.json')
    if not path and getattr(sys, 'frozen', False):
        external = Path(sys.executable).with_name('board_profiles.json')
        if external.exists(): profiles_path = external
    profiles = json.loads(profiles_path.read_text(encoding='utf-8-sig'))
    manifest_hash = hashlib.sha256(profiles_path.read_bytes()).hexdigest()
    for board, profile in profiles.items():
        profile['_manifest_path'] = str(profiles_path.resolve())
        configured = profile.get('configuration_header')
        if not configured: continue
        header = Path(os.path.expandvars(configured)).expanduser()
        if not header.is_absolute():
            header = profiles_path.parent / header
        origin = 'provided_configuration_file'
        if not header.is_file():
            header = profiles_path.parent / profile.get('fallback_header', '')
            origin = 'bundled_configuration_copy'
        if not header.is_file(): raise ValueError('Configuration header missing for ' + board)
        raw = header.read_bytes()
        try: content = raw.decode('utf-8-sig')
        except UnicodeDecodeError: content = raw.decode('gb18030', errors='replace')
        identity = str(header.resolve())
        profile.update(_configuration_path=identity, _configuration_content=re.sub(r'\r+\n|\r', '\n', content),
                       _configuration_origin=origin,
                       _configuration_dependencies={identity: hashlib.sha256(raw).hexdigest(), str(profiles_path.resolve()): manifest_hash})
    return profiles


def build(root, output, version='', board='all-configurations', cancel_path=None, profiles=None):
    root, output = Path(root).resolve(), Path(output).resolve()
    if not root.is_dir():
        raise ValueError('Source directory does not exist')
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=output.stem + '-', suffix='.building', dir=output.parent)
    os.close(descriptor)
    database = None
    try:
        database = sqlite3.connect(temporary)
        database.executescript(SCHEMA)
        profile = None
        if board in BOARD_MACROS:
            profile = (profiles if isinstance(profiles, dict) else read_profiles(profiles))[board]
            primary = ['IS_5728_MCP', 'IS_570_IPB', 'IS_570_OPB', 'IS_570_SIG']
            expected = {name: int(name == BOARD_MACROS[board]) for name in primary}
            if not profile.get('_configuration_path') and any(str(profile['defines'].get(name)) != str(value) for name, value in expected.items()):
                raise ValueError('Board profile must enable exactly the matching primary board macro')
        index = Index(database, root, cancel_path, profile)
        index.load()
        index.collect_functions()
        index.collect_bindings()
        index.collect_calls()
        source_hash = hashlib.sha256('\n'.join(f'{p}:{h}' for p, h in database.execute('SELECT path,sha256 FROM files ORDER BY path')).encode()).hexdigest()
        summary = {table: database.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                   for table in ('files', 'functions', 'calls', 'edges', 'bindings', 'macros', 'log_sites', 'diagnostics')}
        summary['call_kinds'] = dict(database.execute('SELECT kind,count(*) FROM calls GROUP BY kind'))
        summary['indirect_with_candidates'] = database.execute("SELECT count(*) FROM calls WHERE kind='indirect' AND EXISTS(SELECT 1 FROM edges WHERE call_id=calls.id)").fetchone()[0]
        summary['parse_error_files'] = database.execute('SELECT count(*) FROM files WHERE has_errors=1').fetchone()[0]
        metadata = dict(format='logdiagnosis-source-relations', schema_version='1', snapshot_id=str(uuid.uuid4()),
                        created_utc=datetime.now(timezone.utc).isoformat(), source_root=str(root), source_hash=source_hash,
                        software_version=version, board=board, parser='tree-sitter 0.25.2 / tree-sitter-c 0.24.1',
                        analysis_mode='syntax_all_branches', summary=json.dumps(summary, ensure_ascii=False))
        if profile:
            public_profile = {'defines': profile.get('_resolved_defines', profile['defines']), 'closed_world': profile.get('closed_world', False),
                              'ignored_includes': profile.get('ignore_includes', [])}
            if profile.get('_configuration_path'):
                public_profile.update(configuration_header=board + '/PROJECT_OR_BOARD_PTCL.h', configuration_origin=profile['_configuration_origin'])
                dependencies = profile['_configuration_dependencies']
                digest = hashlib.sha256(json.dumps({Path(p).name: h for p, h in dependencies.items()}, sort_keys=True).encode()).hexdigest()
                metadata.update(configuration_sha256=digest, configuration_header_path=profile['_configuration_path'],
                                profile_manifest_path=profile.get('_manifest_path', ''),
                                configuration_dependencies=json.dumps(dependencies),
                                missing_configuration_includes=json.dumps(sorted(index.missing_configuration_includes)))
            metadata.update(analysis_mode='board_scoped_conditionals', board_profile=json.dumps(public_profile),
                            unresolved_configuration=json.dumps(sorted(index.unknown_configuration)),
                            configuration_state=('provided_header_with_missing_includes' if index.missing_configuration_includes else 'provided_header')
                            if profile.get('_configuration_path') else ('partial' if index.unknown_configuration else 'resolved_for_indexed_files'))
        database.executemany('INSERT INTO metadata VALUES(?,?)', metadata.items())
        database.commit()
        if database.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite integrity check failed')
        if database.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('SQLite foreign key check failed')
        database.close()
        database = None
        index.check_cancelled()
        os.replace(temporary, output)
        return summary
    finally:
        if database is not None:
            database.close()
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--version', default='')
    parser.add_argument('--cancel-file', help='Stop safely when this file appears')
    parser.add_argument('--board', default='all-configurations', choices=['all-configurations', 'ATP', 'IPB', 'OPB', 'SPB'])
    parser.add_argument('--all-boards', action='store_true', help='Build four isolated board databases beside the output base')
    parser.add_argument('--profiles', help='JSON file containing actual per-board define/undefine configurations')
    args = parser.parse_args()
    try:
        if args.all_boards:
            base = Path(args.output)
            stem = re.sub(r'\.(ATP|MCP|IPB|OPB|SPB|SIG)$', '', base.stem, flags=re.I)
            profiles = read_profiles(args.profiles)
            summary = {board: build(args.source, base.with_name(stem + '.' + board + base.suffix), args.version,
                                   board, args.cancel_file, profiles) for board in BOARD_MACROS}
        else:
            summary = build(args.source, args.output, args.version, args.board, args.cancel_file, args.profiles)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f'Index failed: {error}\n')


if __name__ == '__main__':
    main()
