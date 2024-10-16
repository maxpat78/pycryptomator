COPYRIGHT = '''Copyright (C)2024, by maxpat78.'''

__all__ = ["split", "quote", "join", "cmd_parse", "cmd_split", "cmd_quote"]
__version__ = '1.0.0'

import os

class NotExpected(Exception):
    def __init__ (p, s):
        super().__init__(s + ' is not expected')


SPLIT_SHELL32 = 0 # CommandLineToArgvW (and pre-2005 VC Runtime) mode (default)
SPLIT_ARGV0   = 1 # full compatibility: simplified parsing of argv[0]
SPLIT_VC2005  = 2 # enable VC2005+ handling of quoted double quote
CMD_VAREXPAND = 4 # expand %variables%
CMD_EXCLMARK  = 8 # expand delayed expansion !variables!


def split(s, mode=SPLIT_SHELL32):
    """Split a command line like CommandLineToArgvW (SHELL32) or old parse_cmdline
    (VC Runtime) with mode=SPLIT_SHELL32 (default). With mode=SPLIT_ARGV0, do
    special simplified parsing for first argument; with mode=SPLIT_VC2005, emulate
    2005 and newer parse_cmdline."""
    argv = []       # resulting arguments list
    arg = ''        # current argument
    quoted = 0      # if current argument is quoted
    backslashes = 0 # backslashes in a row
    quotes = 0      # quotes in a row
    space = 0       # whitespace in a row

    if not s: return []

    # Parse 1st argument (executable pathname) in a simplified way, parse_cmdline conformant.
    # Argument is everything up to first space if unquoted, or second quote otherwise
    if mode&1:
        i=0
        for c in s:
            i += 1
            if c == '"':
                quoted = not quoted
                continue
            if c in ' \t':
                if quoted:
                    arg += c
                    continue
                break
            arg += c
        argv += [arg]
        arg=''
        quoted = 0
        s = s[i:] # strip processed string

    s = s.strip() # strip leading and trailing whitespace
    if not s: return argv
    
    # Special rules:
    # Quotes: " open block; "" open and close block; """ open, add literal " and close block
    # Backslashes, if followed by ":
    #  2n -> n, and open/close block
    #  (2n+1) -> n, and add literal "
    for c in s:
        # count backslashes
        if c == '\\':
            space = 0 # reset count
            backslashes += 1
            continue
        if c == '"':
            space = 0  # reset count
            if backslashes:
                # take 2n, emit n
                arg += '\\' * (backslashes//2)
                if backslashes%2:
                    # if odd, add the escaped literal quote
                    arg += c
                    backslashes = 0
                    continue
                backslashes = 0
            quoted = not quoted
            quotes += 1
            # 3" in a row unquoted or 2" quoted -> add a literal "
            if quotes == 3 or quotes == 2 and quoted:
                arg += c
                quoted = not quoted
                if mode&2:
                    quoted = not quoted # new parse_cmdline does NOT change quoting
                quotes = 0
            continue
        if backslashes:
            # simply append the backslashes
            arg += '\\' * backslashes
        quotes = backslashes = 0
        if c in ' \t':
            if quoted:
                # append whitespace
                arg += c
                continue
            # ignore whitespace in excess between arguments
            if not space:
                # append argument
                argv += [arg]
                arg = ''
            space += 1
            continue
        space = 0
        # append normal char
        arg += c
    if backslashes:
        arg += '\\' * backslashes
    # append last arg
    argv += [arg]
    return argv

def quote(s):
    "Quote a string in a way suitable for the split function"
    backslashes = 0 # backslashes in a row
    if not s: return '""'
    arg = ''
    for c in s:
        # count backslashes
        if c == '\\':
            backslashes += 1
            continue
        if c == '"':
            if backslashes:
                # take n, emit 2n
                arg += '\\' * (2*backslashes)
                backslashes = 0
            # escape the "
            arg += '\\"'
            continue
        if backslashes:
            # add literally
            arg += backslashes*'\\'
            backslashes = 0
        arg += c
    if backslashes:
        # double at end, since we quote hereafter
        arg += (2*backslashes)*'\\'
    arg = '"'+arg+'"' # always quote argument
    return arg

def join(argv):
    "Quote and join list items, so that split returns the same"
    return ' '.join([quote(arg) for arg in argv])

def cmd_parse(s, mode=SPLIT_SHELL32|CMD_VAREXPAND):
    "Pre-process a command line like Windows CMD Command Prompt"
    escaped = 0
    quoted = 0
    percent = 0
    exclamation = 0
    meta = 0 # special chars in a row
    arg = ''
    argv = []

    # remove (ignore) some leading chars
    for c in ' ;,=\t\x0B\x0C\xFF': s = s.lstrip(c)
    
    if not s or s[0] == ':': return []
    
    # push special batch char
    if  s[0] == '@':
        argv = ['@']
        s = s[1:]
    # some combinations at line start are prohibited
    if s[0] in '|&<>':
        raise NotExpected(s[0])
    if len(s)>1 and s[0:2] == '()':
        raise NotExpected(')')

    i = 0
    while i < len(s):
        c = s[i]
        i += 1
        if c == '"':
            if not escaped: quoted = not quoted
        if c == '^':
            if escaped or quoted:
                arg += c
                escaped = 0
            else:
                escaped = 1
            continue
        # %VAR%   -> replace with os.environ['VAR'] *if set* and even if quoted
        # ^%VAR%  -> same as above
        # %VAR^%
        # ^%VAR^% -> keep literal %VAR%
        # %%VAR%% -> replace internal %VAR% only
        if c == '%' and (mode&CMD_VAREXPAND):
            arg += c
            if percent and percent != i-1:
                if not escaped:
                    vname = s[percent:i-1]
                    val = os.environ.get(vname)
                    #~ print('debug: "%s": trying to replace var "%s" with "%s"' %(s,vname,val))
                    if val: arg = arg.replace('%'+vname+'%', val)
                percent = 0
                continue
            percent = i # record percent position
            continue
        if c == '!' and (mode&CMD_EXCLMARK):
            arg += c
            if exclamation and exclamation != i-1:
                if not escaped:
                    vname = s[exclamation:i-1]
                    val = os.environ.get(vname)
                    #~ print('debug: "%s": trying to replace var "%s" with "%s"' %(s,vname,val))
                    if val: arg = arg.replace('!'+vname+'!', val)
                exclamation = 0
                continue
            exclamation = i # record exclamation mark position
            continue
        # pipe, redirection, &, && and ||: break argument, and set aside special char/couple
        # multiple pipe, redirection, &, && and || in sequence are forbidden
        if c in '|<>&':
            if escaped or quoted:
                arg += c
                escaped = 0
                continue
            meta += 1
            # 3 specials in a row is forbidden
            if meta == 3: raise NotExpected(c)
            # if 2 specials undoubled
            if len(argv) >= 2 and argv[-1] in '|<>&' and c != argv[-1]: raise NotExpected(c)
            # push argument, if any, and special char/couple
            if arg: argv += [arg]
            argv += [c]
            # if doubled operator: ||, <<, >>, &&
            if i < len(s) and s[i] == c:
                argv[-1] = 2*c
                i += 1
                meta += 1
            arg = ''
            continue
        if c in ' ,;=\t':
            percent = 0
            # exception (Windows 2000+): starting special char escaped
            if i==2 and escaped and c in ',;=':
                argv += [c]
                escaped = 0
                continue
        else:
            meta = 0
        arg += c
        escaped = 0
    argv += [arg]
    return argv

def cmd_split(s, mode=SPLIT_SHELL32):
    "Post-process with split a command line parsed by cmd_parse (mimic mslex behavior)"
    argv = []
    for tok in cmd_parse(s, mode):
        if tok in ('@','<','|','>','<<','>>','&','&&','||'):
            argv += [tok]
            continue
        argv += split(tok)
    return argv

def cmd_quote(s):
    "Quote a string in a way suitable for the cmd_split function"
    # suitable means [x] == cmd_split(cmd_quote(x))
    arg = ''
    for c in s:
        if c in ('^%!<|>&'): arg += '^' # escape the escapable!
        arg += c
    if (' ' in arg) or ('\\' in arg):
         # quote only when special split chars inside,
         # since quote() always insert into double quotes!
        arg = quote(arg)
    return arg
