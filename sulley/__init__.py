"""Sulley Framework."""
import sulley.blocks
import sulley.instrumentation
import sulley.legos
import sulley.pedrpc
import sulley.primitives
import sulley.sex
import sulley.sessions
import sulley.utils

_ = sulley.utils
BIG_ENDIAN = ">"
LITTLE_ENDIAN = "<"


def s_get(name=None):
    """
    Return the request with the specified name or the current request if name is not specified.

    Use this to switch from global function request manipulation to direct object manipulation.

    Example::

        req = s_get("HTTP BASIC")
        print req.num_mutations()

    The selected request is also set as the default current. (ie: s_switch(name) is implied).

    @type  name: String
    @param name: (Optional, def=None) Name of request to return or current request if name is None.

    @rtype:  blocks.request
    @return: The requested request.
    """
    if not name:
        return sulley.blocks.CURRENT

    # ensure this gotten request is the new current.
    s_switch(name)

    if name not in sulley.blocks.REQUESTS:
        raise sulley.sex.SullyRuntimeError("blocks.REQUESTS NOT FOUND: %s" % name)

    return sulley.blocks.REQUESTS[name]


def s_initialize(name):
    """
    Initialize a new block request.

    All blocks / primitives generated after this call apply to the named request.

    Use s_switch() to jump between factories.

    @type  name: String
    @param name: Name of request
    """
    if name in sulley.blocks.REQUESTS:
        raise sulley.sex.SullyRuntimeError("blocks.REQUESTS ALREADY EXISTS: %s" % name)

    sulley.blocks.REQUESTS[name] = sulley.blocks.request(name)
    sulley.blocks.CURRENT = sulley.blocks.REQUESTS[name]


def s_mutate():
    """Mutate the current request and return False if mutations are exhausted.

    @rtype:  Boolean
    @return: True on mutation success, False if mutations exhausted.
    """
    return sulley.blocks.CURRENT.mutate()


def s_num_mutations():
    """Determine the number of repetitions we will be making.

    @rtype:  Integer
    @return: Number of mutated forms this primitive can take.
    """
    return sulley.blocks.CURRENT.num_mutations()


def s_render():
    """Render out and return the entire contents of the current request.

    @rtype:  Raw
    @return: Rendered contents
    """
    return sulley.blocks.CURRENT.render()


def s_switch(name):
    """Change the currect request to the one specified by "name".

    @type  name: String
    @param name: Name of request
    """
    if name not in sulley.blocks.REQUESTS:
        raise sulley.sex.SullyRuntimeError("blocks.REQUESTS NOT FOUND: %s" % name)

    sulley.blocks.CURRENT = sulley.blocks.REQUESTS[name]


def s_block_start(
    name,
    group=None,
    encoder=None,
    dep=None,
    dep_value=None,
    dep_values=[],
    dep_compare="=="
):
    r"""Open a new block under the current request.

    This routine always returns True so you can make your fuzzer pretty
    with indenting::

        if s_block_start("header"):
            s_static("\x00\\x01")
            if s_block_start("body"):
                ...

    @type  name:        String
    @param name:        Name of block being opened
    @type  group:       String
    @param group:       (Optional, def=None) Name of group to associate this block with
    @type  encoder:     Function Pointer
    @param encoder:     (Optional, def=None) Optional pointer to a function to pass rendered data
                        prior to return
    @type  dep:         String
    @param dep:         (Optional, def=None) Optional primitive whose specific value this block
                        depends on
    @type  dep_value:   Mixed
    @param dep_value:   (Optional, def=None) Value that field "dep" must contain for block to render
    @type  dep_values:  List of Mixed Types
    @param dep_values:  (Optional, def=[]) Values that field "dep" may contain for block to render
    @type  dep_compare: String
    @param dep_compare: (Optional, def="==") Comparison method to use on (==, !=, >, >=, <, <=)
    """
    block = sulley.blocks.block(
        name,
        sulley.blocks.CURRENT,
        group,
        encoder,
        dep,
        dep_value,
        dep_values,
        dep_compare)
    sulley.blocks.CURRENT.push(block)

    return True


def s_block_end(name=None):
    """Close the last opened block.

    Optionally specify the name of the block being closed (purely for aesthetic purposes).

    @type  name: String
    @param name: (Optional, def=None) Name of block to closed.
    """
    sulley.blocks.CURRENT.pop()


def s_checksum(block_name, algorithm="crc32", length=0, endian="<", name=None):
    """Create a checksum block bound to the block with the specified name.

    You *can not* create a checksum for any
    currently open blocks.

    @type  block_name: String
    @param block_name: Name of block to apply sizer to
    @type  algorithm:  String
    @param algorithm:  (Optional, def=crc32) Checksum algorithm to use. (crc32, adler32, md5, sha1)
    @type  length:     Integer
    @param length:     (Optional, def=0) Length of checksum, specify 0 to auto-calculate
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                       (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  name:       String
    @param name:       Name of this checksum field
    """
    # you can't add a checksum for a block currently in the stack.
    if block_name in sulley.blocks.CURRENT.block_stack:
        raise sulley.sex.SullyRuntimeError(
            "CAN N0T ADD A CHECKSUM FOR A BLOCK CURRENTLY IN THE STACK")

    checksum = sulley.blocks.checksum(
        block_name,
        sulley.blocks.CURRENT,
        algorithm,
        length,
        endian,
        name)
    sulley.blocks.CURRENT.push(checksum)


def s_repeat(
    block_name,
    min_reps=0,
    max_reps=None,
    step=1,
    variable=None,
    fuzzable=True,
    name=None
):
    """Repeat the rendered contents of the specified block cycling from min_reps to max_reps.

    By default renders to nothing. This block modifier is useful for fuzzing overflows in table
    entries. This block modifier MUST come after the block it is being applied to.

    @see: Aliases: s_repeater()

    @type  block_name: String
    @param block_name: Name of block to apply sizer to
    @type  min_reps:   Integer
    @param min_reps:   (Optional, def=0) Minimum number of block repetitions
    @type  max_reps:   Integer
    @param max_reps:   (Optional, def=None) Maximum number of block repetitions
    @type  step:       Integer
    @param step:       (Optional, def=1) Step count between min and max reps
    @type  variable:   Sulley Integer Primitive
    @param variable:   (Optional, def=None) An integer primitive which will specify
                       the number of repitions
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:       String
    @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    repeat = sulley.blocks.repeat(
        block_name,
        sulley.blocks.CURRENT,
        min_reps,
        max_reps,
        step,
        variable,
        fuzzable,
        name)
    sulley.blocks.CURRENT.push(repeat)


def s_size(
    block_name,
    offset=0,
    length=4,
    endian="<",
    format="binary",
    inclusive=False,
    signed=False,
    math=None,
    fuzzable=False,
    name=None
):
    """Create a sizer block bound to the block with the specified name.

    You *can not* create a sizer for any currently open blocks.

    @see: Aliases: s_sizer()

    @type  block_name: String
    @param block_name: Name of block to apply sizer to
    @type  offset:     Integer
    @param offset:     (Optional, def=0) Offset to calculated size of block
    @type  length:     Integer
    @param length:     (Optional, def=4) Length of sizer
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                        (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  format:     String
    @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
    @type  inclusive:  Boolean
    @param inclusive:  (Optional, def=False) Should the sizer count its own length?
    @type  signed:     Boolean
    @param signed:     (Optional, def=False) Make size signed vs. unsigned
                        (applicable only with format="ascii")
    @type  math:       Function
    @param math:       (Optional, def=None) Apply the mathematical operations defined in this
                        function to the size
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=False) Enable/disable fuzzing of this sizer
    @type  name:       String
    @param name:       Name of this sizer field
    """
    # you can't add a size for a block currently in the stack.
    if block_name in sulley.blocks.CURRENT.block_stack:
        raise sulley.sex.SullyRuntimeError("CAN NOT ADD A SIZE FOR A BLOCK CURRENTLY IN THE STACK")

    size = sulley.blocks.size(
        block_name,
        sulley.blocks.CURRENT,
        offset,
        length,
        endian,
        format,
        inclusive,
        signed,
        math,
        fuzzable,
        name)
    sulley.blocks.CURRENT.push(size)


def s_update(name, value):
    """Update the value of the named primitive in the currently open request.

    @type  name:  String
    @param name:  Name of object whose value we wish to update
    @type  value: Mixed
    @param value: Updated value
    """
    if name not in sulley.blocks.CURRENT.names:
        raise sulley.sex.SullyRuntimeError(
            "NO OBJECT WITH NAME '%s' FOUND IN CURRENT REQUEST" % name)

    sulley.blocks.CURRENT.names[name].value = value


def s_binary(value, name=None):
    """Parse a variable format binary string into a static value and push it onto stack.

    @type  value: String
    @param value: Variable format binary string
    @type  name:  String
    @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    # parse the binary string into.
    parsed = value
    parsed = parsed.replace(" ", "")
    parsed = parsed.replace("\t", "")
    parsed = parsed.replace("\r", "")
    parsed = parsed.replace("\n", "")
    parsed = parsed.replace(",", "")
    parsed = parsed.replace("0x", "")
    parsed = parsed.replace("\\x", "")

    value = ""
    while parsed:
        pair = parsed[:2]
        parsed = parsed[2:]

        value += chr(int(pair, 16))

    static = sulley.primitives.static(value, name)
    sulley.blocks.CURRENT.push(static)


def s_delim(value, fuzzable=True, name=None):
    """Push a delimiter onto the current block stack.

    @type  value:    Character
    @param value:    Original value
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    delim = sulley.primitives.delim(value, fuzzable, name)
    sulley.blocks.CURRENT.push(delim)


def s_group(name, values):
    """Primitive represents a list of static values, stepping through each one on mutation.

    You can tie a block to a group primitive to specify that the block should cycle through all
    possible mutations for *each* value within the group. The group primitive is useful for example
    for representing a list of valid opcodes.

    @type  name:   String
    @param name:   Name of group
    @type  values: List or raw data
    @param values: List of possible raw values this group can take.
    """
    group = sulley.primitives.group(name, values)
    sulley.blocks.CURRENT.push(group)


def s_lego(lego_type, value=None, options={}):
    """Lego are pre-built blocks."""
    # as legos are blocks they must have a name.
    # generate a unique name for this lego.
    name = "LEGO_%08x" % len(sulley.blocks.CURRENT.names)

    if lego_type not in sulley.legos.BIN:
        raise sulley.sex.SullyRuntimeError("INVALID LEGO TYPE SPECIFIED: %s" % lego_type)

    lego = sulley.legos.BIN[lego_type](name, sulley.blocks.CURRENT, value, options)

    # push the lego onto the stack and immediately pop to close the block.
    sulley.blocks.CURRENT.push(lego)
    sulley.blocks.CURRENT.pop()


def s_random(value, min_length, max_length, num_mutations=25, fuzzable=True, step=None, name=None):
    """Generate a random chunk of data while maintaining a copy of the original.

    A random length range can be specified.
    For a static length, set min/max length to be the same.

    @type  value:         Raw
    @param value:         Original value
    @type  min_length:    Integer
    @param min_length:    Minimum length of random block
    @type  max_length:    Integer
    @param max_length:    Maximum length of random block
    @type  num_mutations: Integer
    @param num_mutations: (Optional, def=25) Number of mutations to make before reverting to default
    @type  fuzzable:      Boolean
    @param fuzzable:      (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  step:          Integer
    @param step:          (Optional, def=None) If not null, step count between min and max reps,
                          otherwise random
    @type  name:          String
    @param name:          (Optional, def=None) Specifying a name gives you direct access to a
                          primitive
    """
    random = sulley.primitives.random_data(
        value,
        min_length,
        max_length,
        num_mutations,
        fuzzable,
        step,
        name)
    sulley.blocks.CURRENT.push(random)


def s_static(value, name=None):
    """Push a static value onto the current block stack.

    @see: Aliases: s_dunno(), s_raw(), s_unknown()

    @type  value: Raw
    @param value: Raw static data
    @type  name:  String
    @param name:  (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    static = sulley.primitives.static(value, name)
    sulley.blocks.CURRENT.push(static)


def s_string(value, size=-1, padding="\x00", encoding="ascii", fuzzable=True, max_len=0, name=None):
    r"""Push a string onto the current block stack.

    @type  value:    String
    @param value:    Default string value
    @type  size:     Integer
    @param size:     (Optional, def=-1) Static size of this field, leave -1 for dynamic.
    @type  padding:  Character
    @param padding:  (Optional, def="\\x00") Value to use as padding to fill static field size.
    @type  encoding: String
    @param encoding: (Optonal, def="ascii") String encoding, ex: utf_16_le for Microsoft Unicode.
    @type  fuzzable: Boolean
    @param fuzzable: (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  max_len:  Integer
    @param max_len:  (Optional, def=0) Maximum string length
    @type  name:     String
    @param name:     (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    s = sulley.primitives.string(value, size, padding, encoding, fuzzable, max_len, name)
    sulley.blocks.CURRENT.push(s)


def s_bit_field(
    value,
    width,
    endian="<",
    format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None
):
    r"""Push a variable length bit field onto the current block stack.

    @see: Aliases: s_bit(), s_bits()

    @type  value:      Integer
    @param value:      Default integer value
    @type  width:      Integer
    @param width:      Width of bit fields
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                       (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  format:     String
    @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
    @type  signed:     Boolean
    @param signed:     (Optional, def=False) Make size signed vs. unsigned (applicable only with
                       format="ascii")
    @type  full_range: Boolean
    @param full_range: (Optional, def=False) If enabled the field mutates through *all* possible
                        values.
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:       String
    @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    bit_field = sulley.primitives.bit_field(
        value,
        width,
        None,
        endian,
        format,
        signed,
        full_range,
        fuzzable,
        name)
    sulley.blocks.CURRENT.push(bit_field)


def s_byte(
    value,
    endian="<",
    format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None
):
    """Push a byte onto the current block stack.

    @see: Aliases: s_char()

    @type  value:      Integer
    @param value:      Default integer value
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                        (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  format:     String
    @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
    @type  signed:     Boolean
    @param signed:     (Optional, def=False) Make size signed vs. unsigned (applicable only with
                        format="ascii")
    @type  full_range: Boolean
    @param full_range: (Optional, def=False) If enabled the field mutates through *all* possible
                        values.
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:       String
    @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    byte = sulley.primitives.byte(value, endian, format, signed, full_range, fuzzable, name)
    sulley.blocks.CURRENT.push(byte)


def s_word(
    value,
    endian="<",
    format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None
):
    """Push a word onto the current block stack.

    @see: Aliases: s_short()

    @type  value:      Integer
    @param value:      Default integer value
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                        (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  format:     String
    @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
    @type  signed:     Boolean
    @param signed:     (Optional, def=False) Make size signed vs. unsigned (applicable only with
                        format="ascii")
    @type  full_range: Boolean
    @param full_range: (Optional, def=False) If enabled the field mutates through *all* possible
                        values.
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:       String
    @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    word = sulley.primitives.word(value, endian, format, signed, full_range, fuzzable, name)
    sulley.blocks.CURRENT.push(word)


def s_dword(
    value,
    endian="<",
    format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None
):
    """Push a double word onto the current block stack.

    @see: Aliases: s_long(), s_int()

    @type  value:      Integer
    @param value:      Default integer value
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                        (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  format:     String
    @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
    @type  signed:     Boolean
    @param signed:     (Optional, def=False) Make size signed vs. unsigned (applicable only with
                        format="ascii")
    @type  full_range: Boolean
    @param full_range: (Optional, def=False) If enabled the field mutates through *all* possible
                        values.
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:       String
    @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    dword = sulley.primitives.dword(value, endian, format, signed, full_range, fuzzable, name)
    sulley.blocks.CURRENT.push(dword)


def s_qword(
    value,
    endian="<",
    format="binary",
    signed=False,
    full_range=False,
    fuzzable=True,
    name=None
):
    """Push a quad word onto the current block stack.

    @see: Aliases: s_double()

    @type  value:      Integer
    @param value:      Default integer value
    @type  endian:     Character
    @param endian:     (Optional, def=LITTLE_ENDIAN) Endianess of the bit field
                        (LITTLE_ENDIAN: <, BIG_ENDIAN: >)
    @type  format:     String
    @param format:     (Optional, def=binary) Output format, "binary" or "ascii"
    @type  signed:     Boolean
    @param signed:     (Optional, def=False) Make size signed vs. unsigned (applicable only with
                        format="ascii")
    @type  full_range: Boolean
    @param full_range: (Optional, def=False) If enabled the field mutates through *all* possible
                        values.
    @type  fuzzable:   Boolean
    @param fuzzable:   (Optional, def=True) Enable/disable fuzzing of this primitive
    @type  name:       String
    @param name:       (Optional, def=None) Specifying a name gives you direct access to a primitive
    """
    qword = sulley.primitives.qword(value, endian, format, signed, full_range, fuzzable, name)
    sulley.blocks.CURRENT.push(qword)


# ALIASES

s_dunno = s_raw = s_unknown = s_static
s_sizer = s_size
s_bit = s_bits = s_bit_field
s_char = s_byte
s_short = s_word
s_long = s_int = s_dword
s_double = s_qword
s_repeater = s_repeat


def custom_raise(argument, msg):
    """Custom exception raising."""
    def _(x):
      raise msg(argument(x))
    return _


def s_intelword(x):
    """Full intel word."""
    return s_long(x, endian=LITTLE_ENDIAN)


def s_intelhalfword(x):
    """Short intel word."""
    return s_short(x, endian=LITTLE_ENDIAN)


def s_bigword(x):
    """Big word."""
    return s_long(x, endian=BIG_ENDIAN)


def s_unistring(x):
    """A unistring."""
    return s_string(x, encoding="utf_16_le")

s_string_lf = custom_raise(
    ValueError,
    "NotImplementedError: s_string_lf is not currently implemented, arguments were")
s_string_or_env = custom_raise(
    ValueError,
    "NotImplementedError: s_string_or_env is not currently implemented, arguments were")
s_string_repeat = custom_raise(
    ValueError,
    "NotImplementedError: s_string_repeat is not currently implemented, arguments were")
s_string_variable = custom_raise(
    ValueError,
    "NotImplementedError: s_string_variable is not currently implemented, arguments were")
s_string_variables = custom_raise(
    ValueError,
    "NotImplementedError: s_string_variables is not currently implemented, arguments were")
s_binary_repeat = custom_raise(
    ValueError,
    "NotImplementedError: s_string_variables is not currently implemented, arguments were")
s_unistring_variable = custom_raise(
    ValueError,
    "NotImplementedError: s_unistring_variable is not currently implemented, arguments were")
s_xdr_string = custom_raise(
    ValueError,
    "LegoNotUtilizedError: XDR strings are available in the XDR lego, arguments were")


def s_cstring(x):
    """A cString."""
    s_string(x)
    s_static("\x00")

s_binary_block_size_intel_halfword_plus_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_halfword_bigendian_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_word_bigendian_plussome = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_word_bigendian_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_halfword_bigendian_mult = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_intel_halfword_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_intel_halfword_mult = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_intel_halfword_plus = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_halfword_bigendian = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_word_intel_mult_plus = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_intel_word_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_word_bigendian_mult = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_blocksize_unsigned_string_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_intel_word_plus = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_intel_halfword = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_word_bigendian = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_blocksize_signed_string_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_byte_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_intel_word = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_byte_plus = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_byte_mult = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_blocksize_asciihex_variable = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_binary_block_size_byte = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_blocksize_asciihex = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")
s_blocksize_string = custom_raise(
    ValueError,
    "SizerNotUtilizedError: Use the s_size primitive for including sizes, arguments were")


def s_hex_dump(data, addr=0):
    """Return the hex dump of the supplied data starting at the offset address specified.

    @type  data: Raw
    @param data: Data to show hex dump of
    @type  addr: Integer
    @param addr: (Optional, def=0) Offset to start displaying hex dump addresses from

    @rtype:  String
    @return: Hex dump of raw data
    """
    dump = slice = ""

    for byte in data:
        if addr % 16 == 0:
            dump += " "

            for char in slice:
                if ord(char) >= 32 and ord(char) <= 126:
                    dump += char
                else:
                    dump += "."

            dump += "\n%04x: " % addr
            slice = ""

        dump += "%02x " % ord(byte)
        slice += byte
        addr += 1

    remainder = addr % 16

    if remainder != 0:
        dump += "   " * (16 - remainder) + " "

    for char in slice:
        if ord(char) >= 32 and ord(char) <= 126:
            dump += char
        else:
            dump += "."

    return dump + "\n"
