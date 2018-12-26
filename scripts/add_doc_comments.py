#!/usr/bin/env python2

"""
Apply a patch that adds Rust doc comments to bindgen-generated Rust source.

To run unittests:
    python -m unittest -v add_doc_comments
"""

# pylint: disable=too-few-public-methods

from __future__ import print_function

import argparse
import logging
import re
import unittest


INDENT_PAT = re.compile(r'^(\s+)\S'.encode())
LOGGER = logging.getLogger(__name__)


_LOGGER_CACHE = {}


def _local_logger():
    import inspect
    name = inspect.stack()[1][3]

    if name in _LOGGER_CACHE:
        return _LOGGER_CACHE[name]

    logger = LOGGER.getChild(name)
    _LOGGER_CACHE[name] = logger
    return logger


class AddDocCommentsBaseException(Exception):
    """Base exception for add_doc_comments module"""
    pass


class InvalidPatchException(AddDocCommentsBaseException):
    """Got a bad formatted patch"""
    pass


class AddDocCommentsException(AddDocCommentsBaseException):
    """Error adding document comments to a file"""
    pass


class DocCommentInsertIndexBaseException(AddDocCommentsBaseException):
    """Base exception for doc_comment_insert_index"""
    pass


class DocCommentsNoMatchException(DocCommentInsertIndexBaseException):
    """No match was found for the doc comment"""
    pass


class DocCommentsMultipleMatchesException(DocCommentInsertIndexBaseException):
    """
    Multiple matches were found for the doc comment

    :ivar Optional[List[int]] candidate_indices: candidate insert indices
    """
    def __init__(self, *args, **kwargs):
        self.candidate_indices = None
        DocCommentInsertIndexBaseException.__init__(self, *args, **kwargs)


def patch_plus_parts(patch):
    """
    Yields a "sliding window" over the additive parts of the patch.

    :param str patch: patch/diff
    :return: (prefix_lines, plus_lines, suffix_lines)
    :rtype: (List[str], List[str], List[str])
    """

    class State(object):
        """Parser state"""
        WAIT_ADD, ON_ADD = range(2)

    logger = _local_logger()

    # Convert unicode types to bytes
    if not isinstance(patch, bytes):
        patch = patch.encode()

    state = State.WAIT_ADD
    prefix_lines = []
    plus_lines = []
    suffix_lines = []
    seen_plus = False

    for line in patch.split(b'\n'):
        # Skip empty lines
        if not line:
            continue

        # Skip these lines
        splits = line.split()
        if splits and splits[0] in [b'diff', b'index', b'---', b'+++', b'@@']:
            continue

        logger.debug('state=%d, prefix=%s, plus=%s, suffix=%s, seen_plus=%s',
                     state, prefix_lines, plus_lines, suffix_lines, seen_plus)

        # We avoid using a single index [0] because Python3 returns an int
        first_char, line = line[0:1], line[1:]
        if first_char == b'+':
            if state == State.WAIT_ADD:
                state = State.ON_ADD
                if seen_plus:
                    yield prefix_lines, plus_lines, suffix_lines
                    # Do a shallow copy to avoid weird aliasing
                    prefix_lines = suffix_lines[:]
                plus_lines = []
                suffix_lines = []
            seen_plus = True
            plus_lines.append(line)
        elif first_char == b'-':
            # ignore minus lines
            continue
        elif first_char == b' ':
            # Context line
            if state == State.ON_ADD:
                state = State.WAIT_ADD

            context_lines = suffix_lines if seen_plus else prefix_lines
            context_lines.append(line)
        else:
            raise InvalidPatchException(
                'Invalid patch line %s; does not start with "+- "' % repr(line))

    yield prefix_lines, plus_lines, suffix_lines


def _decode_all(iterable):
    return [x.encode() for x in iterable]


class TestPatchParts(unittest.TestCase):
    # pylint: disable=missing-docstring

    def patch_part_test(self, patch, parts):
        parts = [(_decode_all(pre), _decode_all(plus), _decode_all(post))
                 for (pre, plus, post) in parts]
        self.assertEqual(list(patch_plus_parts(patch)), parts)

    def test_simple_1_part_short(self):
        self.patch_part_test(
            ' a\n+b\n c\n',
            [(['a'], ['b'], ['c'])])

    def test_simple_1_part_long(self):
        self.patch_part_test(
            ' a1\n a2\n a3\n+b1\n+b2\n+b3\n c1\n c2\n c3\n',
            [(['a1', 'a2', 'a3'], ['b1', 'b2', 'b3'], ['c1', 'c2', 'c3'])])

    def test_simple_2_part_short(self):
        self.patch_part_test(
            ' a\n+b\n c\n+d\n e\n',
            [(['a'], ['b'], ['c']),
             (['c'], ['d'], ['e'])]
        )

    def test_simple_3_part_short(self):
        self.patch_part_test(
            ' a\n+b\n c\n+d\n e\n+f\n g\n',
            [(['a'], ['b'], ['c']),
             (['c'], ['d'], ['e']),
             (['e'], ['f'], ['g'])
            ]
        )

    def test_no_suffix_context(self):
        self.patch_part_test(
            ' a\n+b\n c\n+d\n e\n+f\n g\n+h\n',
            [(['a'], ['b'], ['c']),
             (['c'], ['d'], ['e']),
             (['e'], ['f'], ['g']),
             (['g'], ['h'], [])
            ]
        )

    def test_no_prefix_context(self):
        self.patch_part_test(
            '+b\n c\n+d\n e\n+f\n g\n',
            [([], ['b'], ['c']),
             (['c'], ['d'], ['e']),
             (['e'], ['f'], ['g'])
            ]
        )


# Example: 'CS_MODE_LITTLE_ENDIAN = 0,',
RUST_IDENT_PAT = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*|_[a-zA-Z0-9_]+$'.encode())


def is_rust_ident(ident):
    """Returns whether a string is a valid rust identifier"""
    if not isinstance(ident, bytes):
        ident = ident.encode()
    return RUST_IDENT_PAT.match(ident)


class TestIsRustIdent(unittest.TestCase):
    # pylint: disable=missing-docstring

    def test_underscore(self):
        self.assertFalse(is_rust_ident('_'))

    def test_1num(self):
        self.assertFalse(is_rust_ident('1'))

    def test_2num(self):
        self.assertFalse(is_rust_ident('12'))

    def test_under_1num(self):
        self.assertTrue(is_rust_ident('_1'))

    def test_under_2num(self):
        self.assertTrue(is_rust_ident('_12'))

    def test_1let(self):
        self.assertTrue(is_rust_ident('a'))

    def test_2let(self):
        self.assertTrue(is_rust_ident('ab'))

    def test_1let_1num(self):
        self.assertTrue(is_rust_ident('a1'))

    def test_real1(self):
        self.assertTrue(is_rust_ident('CS_MODE_LITTLE_ENDIAN'))


def rust_def_name(rust_expr):
    """
    Returns the Rust "identifier" defined in a Rust expression, otherwise None.

    This assumes rust_expr is "simplified" and has no leading or trailing
    whitespace.

    :param str rust_expr: Line of Rust code that may define a type
    :return: defined Rust type
    :rtype: str
    """
    logger = _local_logger()
    splits = rust_expr.split()

    def find_def_with_trailing(splits_start, extract_def):
        """
        Find a definition that starts with given splits

        :type extract_def: (str) -> str
        """
        sub_split_len = len(splits_start)
        if not (len(splits) >= sub_split_len + 1 and
                splits[:sub_split_len] == splits_start):
            return None

        name_part = splits[sub_split_len]
        def_name = extract_def(name_part)
        logger.debug('Returning rust_def_name %s from %s',
                     def_name, repr(rust_expr))
        return def_name

    def extract_trailer(trailer):
        """Extracts fn name from fn_part"""
        def func(fn_part):
            """Function to be returned"""
            try:
                trailer_index = fn_part.index(trailer)
                return fn_part[:trailer_index]
            except ValueError:
                return fn_part

        return func

    two_index_tokens = [b'mod', b'type', b'enum', b'struct']
    for token in two_index_tokens:
        if len(splits) >= 3 and splits[:2] == [b'pub', token]:
            def_name = splits[2]
            logger.debug('Returning rust_def_name %s from %s',
                         def_name, repr(rust_expr))
            try:
                select_idx = def_name.index('(')
            except ValueError:
                select_idx = len(def_name)
            return def_name[:select_idx]

    def_with_trailing_args = [
        ([b'pub', b'fn'], extract_trailer(b'(')),
        ([b'pub', b'const'], extract_trailer(b':')),
    ]
    for args in def_with_trailing_args:
        candidate = find_def_with_trailing(*args)
        if candidate:
            return candidate

    # Example: 'CS_MODE_LITTLE_ENDIAN = 0,',
    if len(splits) == 3 and is_rust_ident(splits[0]) and splits[1] == b'=':
        return splits[0]

    return None


class TestRustDefName(unittest.TestCase):
    # pylint: disable=missing-docstring

    def run_test(self, rust_expr, expected_def):
        self.assertEqual(rust_def_name(rust_expr.encode()),
                         expected_def.encode())

    def test_enum(self):
        self.run_test('pub enum cs_arch {', 'cs_arch')

    def test_mod(self):
        self.run_test('pub mod cs_arch {', 'cs_arch')

    def test_const1(self):
        self.run_test(
            'pub const CS_MODE_MIPS32: cs_mode = cs_mode::CS_MODE_32;',
            'CS_MODE_MIPS32')

    def test_const2(self):
        self.run_test(
            'pub const CS_MODE_LITTLE_ENDIAN: Type = 0;',
            'CS_MODE_LITTLE_ENDIAN')

    def test_const3(self):
        self.run_test(
            'CS_MODE_LITTLE_ENDIAN = 0,',
            'CS_MODE_LITTLE_ENDIAN')

    def test_type(self):
        self.run_test(
            'pub type csh = usize;',
            'csh')

    def test_fn1(self):
        self.run_test(
            'pub fn cs_malloc(handle: csh) -> *mut cs_insn;',
            'cs_malloc')

    def test_fn2(self):
        self.run_test(
            'pub fn cs_malloc(',
            'cs_malloc')

    def test_fn3(self):
        self.run_test(
            'pub fn cs_reg_name(handle: csh, reg_id: ::std::os::raw::c_uint)',
            'cs_reg_name')

    def test_tuple_struct(self):
        self.run_test(
            'pub struct cs_mode(pub i32);',
            'cs_mode')


def _simplify(str_):
    """Simplify source line"""
    return str_.strip()


def doc_comment_insert_index(doc_lines, context_line, fs_path_rust_defs):

    """Find where to insert based on context"""

    candidate_indices = []
    context_line_simple = _simplify(context_line)
    def_name = rust_def_name(context_line_simple)

    for idx, candidate_line in enumerate(doc_lines):
        if isinstance(candidate_line, InsertLines):
            continue

        while True:
            candidate_line_simple = _simplify(candidate_line)

            if def_name and def_name == fs_path_rust_defs.get(
                    candidate_line_simple):
                lines_match = True
                break

            lines_match = context_line_simple == candidate_line_simple
            break

        if lines_match:
            candidate_indices.append(idx)

    if not candidate_indices:
        raise DocCommentsNoMatchException()
    if len(candidate_indices) == 1:
        return candidate_indices[0]

    mult_matches = DocCommentsMultipleMatchesException(
        'Found multiple insert indices %s for context line %s' %
        candidate_indices, repr(context_line))
    mult_matches.candidate_indices = candidate_indices
    raise mult_matches


class InsertLines(object):
    """
    Wrapper around a list of strings that shows the line was manually
    inserted

    :ivar List[str | InsertLines] inner: list of internal strings
    :ivar str indent: indent to prefix each line with
    """

    def __init__(self, inner, indent=None):
        self.inner = inner
        self.indent = indent

    def __str__(self):
        indent_str = self.indent if self.indent else b''
        return b''.join(
            rstrip_line(b'%s%s\n' % (indent_str, bytes(x).lstrip()))
            for x in self.inner)

    def __bytes__(self):
        return self.__str__()

    def __repr__(self):
        return 'InsertLines(%s)' % repr(self.inner)


def rstrip_line(line):
    """Removes trailing whitespace from a string (preserving any newline)"""
    if line[-1] == '\n':
        return line[:-1].rstrip() + '\n'
    return line.rstrip()


def add_doc_comments(doc_patch, fs_path, output_path):
    """
    Add Rust doc comments to a file from a commit that added ONLY doc comments

    :param file doc_patch: patch that added doc comments
    :param str fs_path: path to file that needs doc comments added
    :param str output_path: path to file that should be written with with doc
        comments
    """

    # pylint: disable=too-many-locals

    logger = _local_logger()
    patch = doc_patch.read()

    with open(fs_path, 'rb') as fs_path_file:
        # type: List[Union[str, InsertLines]]
        doc_lines = list(fs_path_file.readlines())

    matched_parts = 0
    total_parts = 0

    logger.info('Pre-computing rust_def_names')
    fs_path_rust_defs = {}
    for line in doc_lines:
        line = _simplify(line)
        line_def = rust_def_name(line)
        if line_def:
            fs_path_rust_defs[line] = line_def
    logger.info('Done pre-computing rust_def_names')

    for _, plus_lines, post_lines in patch_plus_parts(patch):
        logger.info('Plus lines: %s', plus_lines)
        logger.info('Post context: %s', post_lines)

        total_parts += 1

        if not post_lines:
            logger.debug('Skipping part, no post context lines')
            continue

        # Only look at one line of context
        context_line = post_lines[0]

        try:
            insert_index = doc_comment_insert_index(doc_lines, context_line,
                                                    fs_path_rust_defs)
            logger.info('CONTEXT: found context line for %s',
                        repr(context_line))
            doc_lines.insert(insert_index, InsertLines(plus_lines))
            matched_parts += 1
        except DocCommentsNoMatchException:
            logger.info('NO CONTEXT: found no context lines for %s',
                        repr(context_line))
        except DocCommentsMultipleMatchesException as exc:
            logger.info('NO CONTEXT: mound multiple indices %s for %s',
                        exc.candidate_indices, repr(context_line))

    with open(output_path, 'wb') as output_file:
        for idx, line in enumerate(doc_lines):
            if isinstance(line, InsertLines):
                try:
                    context_line = doc_lines[idx + 1]
                    indent_matches = INDENT_PAT.findall(context_line)
                    line.indent = indent_matches[0] if indent_matches else None
                except IndexError:
                    pass
            output_file.write(rstrip_line(bytes(line)))

    logger.warning('Matched %d / %d patch parts', matched_parts, total_parts)


def setup_logger(verbosity):
    """Set up module level ogger"""
    levels = [logging.WARN, logging.INFO, logging.DEBUG]
    level_index = min(verbosity, len(levels) - 1)
    logging.basicConfig()
    LOGGER.setLevel(levels[level_index])


EPILOG = """
Example usage:

git diff e67b72b8^ e67b72b8 | \\
    ./scripts/add_doc_comments.py \\
    --doc-patch - \\
    --fs-path pre_generated/capstone.rs \\
    -o pre_generated/capstone.doc.rs
"""


def main():
    """Main driver"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter, epilog=EPILOG)
    parser.add_argument('--doc-patch', '-p', type=argparse.FileType('rb'),
                        required=True,
                        help='File with patch (or - for stdin)')
    parser.add_argument('--fs-path', required=True,
                        help='Path to documented file in current filesystem')
    output_mutex = parser.add_mutually_exclusive_group(required=True)
    output_mutex.add_argument('--in-place', '-i', action='store_true',
                              help='Update fs-path in-place')
    output_mutex.add_argument('--output', '-o',
                              help='Output Rust source with doc comments added')
    parser.add_argument(
        '--verbose', '-v', action='count', default=0,
        help='Log more verbosely (can be passed multiple times)')
    args = parser.parse_args()

    setup_logger(args.verbose)
    LOGGER.info(
        'Set verbosity to %s',
        logging.getLevelName(logging.getLogger().level))

    if args.in_place:
        output_path = args.fs_path
    else:
        output_path = args.output

    add_doc_comments(args.doc_patch, args.fs_path, output_path)


if __name__ == '__main__':
    main()
