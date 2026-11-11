import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from index_source import build, constant, read_profiles


class SourceIndexTests(unittest.TestCase):
    def test_configuration_path_is_relative_to_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'board_config' / 'ATP'
            config.mkdir(parents=True)
            header = config / 'PROJECT_OR_BOARD_PTCL.h'
            header.write_text('#define IS_5728_MCP 1\n', encoding='utf-8')
            manifest_dir = root / 'source_relations'
            manifest_dir.mkdir()
            manifest = manifest_dir / 'board_profiles.json'
            manifest.write_text(json.dumps({'ATP': {
                'configuration_header': '../board_config/ATP/PROJECT_OR_BOARD_PTCL.h',
                'defines': {},
            }}), encoding='utf-8')
            profile = read_profiles(manifest)['ATP']
            self.assertEqual(Path(profile['_configuration_path']), header.resolve())
            self.assertIn(str(header.resolve()), profile['_configuration_dependencies'])
            self.assertEqual(profile['_configuration_origin'], 'provided_configuration_file')

    def test_scope_callbacks_logs_and_conditions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'a.c').write_text('''
#define CODE 0x0A1Au
typedef struct { void (*run)(void); } VTable;
static void same(void) {}
void target(void) {}
static VTable table = { /* callback */ target };
VTable *get_table(void) { return &table; }
void invoke(VTable *v) { v->run(); }
void caller(void) {
 get_table();
 same();
#if BOARD_A
 DarkLogPrint(1, &value, CODE, 4);
#else
 same();
#endif
}
void shadow(void (*target)(void)) { target(); }
''', encoding='utf-8')
            (root / 'b.c').write_text('static void same(void) {}\nvoid b(void) {same();}', encoding='utf-8')
            output = root / 'index.sqlite'
            with contextlib.redirect_stdout(io.StringIO()):
                summary = build(root, output)
            with contextlib.closing(sqlite3.connect(output)) as db:
                self.assertEqual(db.execute('SELECT code FROM log_sites').fetchone()[0], 0x0A1A)
                rows = db.execute("SELECT s.path FROM edges e JOIN call_details c ON c.id=e.call_id JOIN functions t ON t.id=e.target_id JOIN files s ON s.id=t.file_id WHERE c.caller='b'").fetchall()
                self.assertEqual(rows, [('b.c',)])
                self.assertEqual(db.execute("SELECT count(*) FROM edges e JOIN call_details c ON c.id=e.call_id WHERE c.caller='shadow'").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT kind FROM call_details WHERE name='get_table'").fetchone()[0], 'direct')
                self.assertEqual(db.execute("SELECT t.name FROM edges e JOIN call_details c ON c.id=e.call_id JOIN functions t ON t.id=e.target_id WHERE c.caller='invoke'").fetchone()[0], 'target')
                self.assertIn('BOARD_A', db.execute('SELECT condition FROM call_details WHERE id=(SELECT call_id FROM log_sites)').fetchone()[0])
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(summary['files'], 2)
            before = output.read_bytes()
            with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                build(root / 'missing', output)
            self.assertEqual(before, output.read_bytes())
            cancellation = root / 'cancel'
            cancellation.touch()
            with self.assertRaises(ValueError), contextlib.redirect_stdout(io.StringIO()):
                build(root, output, cancel_path=cancellation)
            self.assertEqual(before, output.read_bytes())
            self.assertEqual(list(root.glob('*.building')), [])

    def test_safe_macro_values(self):
        self.assertEqual(constant('(BASE | 2u)', {'BASE': {'0x1000'}}), 0x1002)
        self.assertIsNone(constant('CODE', {'CODE': {'1', '2'}}))
        self.assertIsNone(constant('A', {'A': {'B'}, 'B': {'A'}}))
        self.assertIsNone(constant('__import__("os").system("bad")', {}))

    def test_four_board_branches_are_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'local.h').write_text('#ifndef LOCAL_H // guard\n#define LOCAL_H\n#define LOCAL_SWITCH 1\n#endif\n', encoding='utf-8')
            source = '#include "local.h"\n#define CODE 0x0084\n'
            for index, (board, macro) in enumerate([('ATP','IS_5728_MCP'),('IPB','IS_570_IPB'),('OPB','IS_570_OPB'),('SPB','IS_570_SIG')]):
                source += ('#if ' if index == 0 else '#elif ') + macro + ' == 1\n'
                source += f'void shared(void) {{ DarkLogPrint(1, &value_{board}, CODE, 1); }}\n'
            source += '#endif\n#if UNKNOWN_FEATURE\nvoid unknown_a(void) {}\n#else\nvoid unknown_b(void) {}\n#endif\n'
            source += '#if LOCAL_SWITCH\nvoid local_active(void) {}\n#endif\n'
            source += '/*\n#if IS_570_SIG\n*/\nvoid comment_is_not_directive(void) {}\n'
            (root / 'a.c').write_bytes(source.replace('\n', '\r\r\n').encode())
            for board in ('ATP', 'IPB', 'OPB', 'SPB'):
                output = root / (board + '.sqlite')
                macros = {'ATP': 'IS_5728_MCP', 'IPB': 'IS_570_IPB', 'OPB': 'IS_570_OPB', 'SPB': 'IS_570_SIG'}
                profile = {'defines': {name: str(int(role == board)) for role, name in macros.items()},
                           'closed_world': True, 'expected_board_macro': macros[board]}
                with contextlib.redirect_stdout(io.StringIO()): build(root, output, board=board, profiles={board: profile})
                with contextlib.closing(sqlite3.connect(output)) as db:
                    self.assertEqual(db.execute('SELECT data_expression FROM log_sites').fetchall(), [('&value_' + board,)])
                    self.assertEqual(db.execute("SELECT count(*) FROM functions WHERE name='unknown_a'").fetchone()[0], 0)
                    self.assertEqual(db.execute("SELECT count(*) FROM functions WHERE name='unknown_b'").fetchone()[0], 1)
                    self.assertEqual(db.execute("SELECT count(*) FROM functions WHERE name='local_active'").fetchone()[0], 1)
                    self.assertEqual(db.execute("SELECT count(*) FROM functions WHERE name='comment_is_not_directive'").fetchone()[0], 1)
                    self.assertEqual(db.execute("SELECT value FROM metadata WHERE key='board'").fetchone()[0], board)


if __name__ == '__main__':
    unittest.main()
