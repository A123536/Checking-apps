"""Exclude inactive board branches and retain unresolved feature branches as candidates."""
import re
from pcpp import Preprocessor


class Expressions(Preprocessor):
    def __init__(self, profile):
        super().__init__()
        self.profile_closed = profile.get('closed_world', False)
        self.unknown = set()
        self.undefined = set(profile.get('undefines', [])) | {'__cplusplus'}
        for name, value in profile['defines'].items():
            self.define(name + ' ' + str(value))

    def on_unknown_macro_in_expr(self, name):
        if name in self.undefined or self.profile_closed:
            return 0
        self.unknown.add(name)
        return None

    def on_unknown_macro_in_defined_expr(self, token):
        if token.value in self.undefined or self.profile_closed:
            return False
        self.unknown.add(token.value)
        return None

    def on_unknown_macro_function_in_expr(self, name):
        self.unknown.add(name)
        return None

    def on_error(self, file, line, message):
        raise ValueError(message)

    def value(self, expression):
        expression = re.sub(r'/\*.*?\*/|//.*', '', expression).strip()
        while expression.startswith('(') and expression.endswith(')'):
            depth = 0
            for index, char in enumerate(expression):
                depth += (char == '(') - (char == ')')
                if depth == 0:
                    break
            if index != len(expression) - 1:
                break
            expression = expression[1:-1].strip()
        for operator in ('||', '&&'):
            depth = 0
            for index, char in enumerate(expression):
                depth += (char == '(') - (char == ')')
                if depth == 0 and expression[index:index + 2] == operator:
                    left = self.value(expression[:index])
                    right = self.value(expression[index + 2:])
                    if operator == '||':
                        return True if left is True or right is True else (False if left is False and right is False else None)
                    return False if left is False or right is False else (True if left is True and right is True else None)
        if expression.startswith('!') and not expression.startswith('!='):
            result = self.value(expression[1:])
            return None if result is None else not result
        try:
            result, unresolved = self.evalexpr(self.tokenize(expression))
            return bool(result) if unresolved is None else None
        except (ValueError, TypeError, IndexError):
            return None


def and_value(left, right):
    if left is False or right is False:
        return False
    return True if left is True and right is True else None


def or_value(left, right):
    if left is True or right is True:
        return True
    return False if left is False and right is False else None


def without_comments(value, in_block):
    output, position = [], 0
    token = re.compile(r'/\*|//|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
    while position < len(value):
        if in_block:
            end = value.find('*/', position)
            if end < 0:
                return ''.join(output), True
            position, in_block = end + 2, False
            output.append(' ')
            continue
        match = token.search(value, position)
        if not match:
            output.append(value[position:])
            break
        output.append(value[position:match.start()])
        if match.group() == '//':
            break
        if match.group() == '/*':
            in_block = True
        else:
            output.append(match.group())
        position = match.end()
    return ''.join(output), in_block


def specialize(content, profile, include_loader=None, source='', evaluator=None, include_stack=None):
    top_level = evaluator is None
    evaluator = evaluator or Expressions(profile)
    include_stack = set() if include_stack is None else include_stack
    if top_level and profile.get('_configuration_content'):
        config_path = profile['_configuration_path']
        specialize(profile['_configuration_content'], profile, include_loader, config_path, evaluator, {config_path})
        if profile.get('_has_missing_configuration_include'):
            evaluator.profile_closed = False
        profile['_resolved_defines'] = {name: ''.join(str(token.value) for token in macro.value)
                                        for name, macro in evaluator.macros.items() if not name.startswith('__')}
    # Conventional include guards are local to each independently indexed file.
    guard = re.search(r'^\s*#\s*ifndef\s+(\w+)[^\n]*\n\s*#\s*define\s+\1\b', content, re.M)
    if guard and guard.group(1) not in evaluator.macros:
        evaluator.undefined.add(guard.group(1))
    lines = content.splitlines(keepends=True)
    output, unresolved, stack = [], [], []
    active = True
    in_comment = False
    index = 0
    while index < len(lines):
        first = index + 1
        original = lines[index]
        index += 1
        while original.rstrip('\r\n').endswith('\\') and index < len(lines):
            original += lines[index]
            index += 1
        logical = re.sub(r'\\\r?\n', '', original)
        logical, in_comment = without_comments(logical, in_comment)
        directive = re.match(r'^\s*#\s*(\w+)\b(.*)', logical, re.S)
        emit = active is not False
        if directive:
            kind, argument = directive.groups()
            argument = argument.strip()
            if kind in ('if', 'ifdef', 'ifndef'):
                argument = re.sub(r'/\*.*?\*/|//[^\n]*', '', argument).strip()
                expression = argument if kind == 'if' else ('!' if kind == 'ifndef' else '') + 'defined(' + argument + ')'
                value = evaluator.value(expression) if active is not False else False
                if active is not False and value is None:
                    unresolved.append((first, expression))
                frame = dict(parent=active, taken=value, passthrough=active is not False and value is None)
                stack.append(frame)
                active = and_value(active, value)
                emit = frame['passthrough']
            elif kind in ('elif', 'else') and stack:
                frame = stack[-1]
                parent, taken = frame['parent'], frame['taken']
                value = evaluator.value(argument) if kind == 'elif' and parent is not False and taken is not True else (True if kind == 'else' else False)
                if kind == 'elif' and parent is not False and value is None:
                    unresolved.append((first, argument))
                remaining = None if taken is None else not taken
                active = and_value(parent, and_value(remaining, value))
                if not frame['passthrough'] and parent is not False and taken is False and value is None:
                    frame['passthrough'] = True
                    original = re.sub(r'(#\s*)elif\b', r'\1if', original, count=1)
                frame['taken'] = or_value(taken, value)
                emit = frame['passthrough']
            elif kind == 'endif' and stack:
                frame = stack.pop()
                active = frame['parent']
                emit = frame['passthrough']
            elif kind in ('define', 'undef'):
                name = re.match(r'\w+', argument)
                if name:
                    name = name.group()
                    if active is True:
                        evaluator.undefined.discard(name)
                        if kind == 'define':
                            evaluator.define(argument)
                        else:
                            evaluator.undef(name)
                            evaluator.undefined.add(name)
                    elif active is None:
                        evaluator.macros.pop(name, None)
                        evaluator.undefined.discard(name)
            elif kind == 'include' and active is True and include_loader:
                match = re.match(r'[<"]([^>"]+)[>"]', argument)
                if match:
                    included = include_loader(match.group(1), source)
                    if included:
                        included_path, included_content = included
                        if included_path not in include_stack and len(include_stack) < 64:
                            specialize(included_content, profile, include_loader, included_path, evaluator,
                                       include_stack | {included_path})
        output.append(original if emit else ''.join('\n' if c == '\n' else ' ' for c in original))
    if top_level:
        for name in ('IS_5728_MCP', 'IS_570_IPB', 'IS_570_OPB', 'IS_570_SIG'):
            value, pending = evaluator.evalexpr(evaluator.tokenize(name))
            expected = int(name == profile['expected_board_macro']) if profile.get('expected_board_macro') else int(profile['defines'][name])
            if pending is not None or int(value) != expected:
                raise ValueError('Source header overrides board profile macro ' + name)
    return ''.join(output), unresolved, sorted(evaluator.unknown)
