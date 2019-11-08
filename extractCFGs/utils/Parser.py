#!/usr/bin/python3


"""
Parser ASM and C++ source code
"""
class Rules(object):

    asmRules = [
        ('TAB', '\t'), 
        ('COMMA', ','),
        ('PERSENT', '%'),    # %eax
        ('NEGATIVE', '-'),   # -10
        ('LBRACK', '('),    # 10(%eax)
        ('RBRACK', ')'),   # 10(%eax)
        ('DOLAR', '$'),    # $1000
        ('DOT', '.')
    ]   # .refptr._ZSt4cout
    
    # Literals (class, int, const, float, string, char)
    # Operators (+,-,*,/,%,|,&,~,^,<<,>>, ||, &&, !, <, <=, >, >=, ==, !=, ::)
    # Assignment (=, *=, /=, %=, +=, -=, <<=, >>=, &=, ^=, |=)
    # Increment/decrement (++,--)
    # Structure dereference (->)
    # Ternary operator (?)
    # Delimeters ( ) [ ] { } , . ; :
    # Ellipsis (...)

    cppReservedWords = [
        '<<=', '>>=', '...',
        '<<', '>>', '||', '&&', '!=', '<=', '>=', '==', '::',
        '*=', '/=', '%=', '+=', '-=', '&=', '^=', '|=', '++', '--', '->',
        '<', '+', '-', '*', '/', '%', '|', '&', '~', '^', '>', '?', '!',
        '(', ')', '[', ']', '{', '}', ',', '.', ';', ':'
    ]

    # cppRules = [
    #     ('LSHIFTEQUAL', '<<='),
    #     ('RSHIFTEQUAL', '>>='),
    #     ('ELLIPSIS', '...'),

    #     ('LSHIFT', '<<'),
    #     ('RSHIFT', '>>'),
    #     ('LOR', '||'),
    #     ('LAND', '&&'),
    #     ('NE', '!='),
    #     ('LE', '<='),
    #     ('GE', '>='),
    #     ('EQ', '=='),
    #     ('SPACE', '::'),

    #     ('TIMESEQUAL', '*='),
    #     ('DIVEQUAL', '/='),
    #     ('MODEQUAL', '%='),
    #     ('PLUSEQUAL', '+='),
    #     ('MINUSEQUAL', '-='),
    #     ('ANDEQUAL', '&='),
    #     ('XOREQUAL', '^='),
    #     ('OREQUAL', '|='),
    #     ('INCREMENT', '++'),
    #     ('DECREMENT', '--'),
    #     ('ARROW', '->'),

    #     ('LT', '<'),
    #     ('PLUS', '+'),
    #     ('MINUS', '-'),
    #     ('TIMES', '*'),
    #     ('DIVIDE', '/'),
    #     ('MODULO', '%'),
    #     ('OR', '|'),
    #     ('AND', '&'),
    #     ('NOT', '~'),
    #     ('XOR', '^'),
    #     ('GT', '>'),
    #     ('TERNARY', '?'),
    #     ('LNOT', '!'),

    #     ('LPAREN', '('),
    #     ('RPAREN', ')'),
    #     ('LBRACKET', '['),
    #     ('RBRACKET', ']'),
    #     ('LBRACE', '{'),
    #     ('RBRACE', '}'),
    #     ('COMMA', ','),
    #     ('PERIOD', '.'),
    #     ('SEMI', ';'),
    #     ('COLON', ':'),
    #     ('DQ', '"'),
    #     ('SQ', '\''),
    #     ('CCCCC', '\\'),
    #     ('ENTER', '\n'),
    #     ('TTTTT', '\t'),
    #     ('EEEEE', '=')
    # ]

    cppRules = [
        ('RULES001', '<<='),
        ('RULES002', '>>='),
        ('RULES003', '...'),

        ('RULES004', '<<'),
        ('RULES005', '>>'),
        ('RULES006', '||'),
        ('RULES007', '&&'),
        ('RULES008', '!='),
        ('RULES009', '<='),
        ('RULES010', '>='),
        ('RULES011', '=='),
        ('RULES012', '::'),

        ('RULES013', '*='),
        ('RULES014', '/='),
        ('RULES015', '%='),
        ('RULES016', '+='),
        ('RULES017', '-='),
        ('RULES018', '&='),
        ('RULES019', '^='),
        ('RULES020', '|='),
        ('RULES021', '++'),
        ('RULES022', '--'),
        ('RULES023', '->'),
        ('RULES037', '**'),

        ('RULES024', '<'),
        ('RULES025', '+'),
        ('RULES026', '-'),
        ('RULES027', '*'),
        ('RULES028', '/'),
        ('RULES029', '%'),
        ('RULES030', '|'),
        ('RULES031', '&'),
        ('RULES032', '~'),
        ('RULES033', '^'),
        ('RULES034', '>'),
        ('RULES035', '?'),
        ('RULES036', '!'),

        ('RULES038', '('),
        ('RULES039', ')'),
        ('RULES040', '['),
        ('RULES041', ']'),
        ('RULES042', '{'),
        ('RULES043', '}'),
        ('RULES044', ','),
        ('RULES045', '.'),
        ('RULES046', ';'),
        ('RULES047', ':'),
        ('RULES048', '"'),
        ('RULES049', '\''),
        ('RULES050', '\\'),
        ('RULES051', '\n'),
        ('RULES052', '\t'),
        ('RULES053', '=')
    ]

    def __init__(self, codeType, code):
        self.pcode = code
        if codeType == 'asm':
            self.parser(self.asmRules)
        elif codeType == 'cpp':
            self.parser(self.cppRules)
        else:
            print("Invalid Code Type")
        return

    """
    replace the rules
    """
    def parser(self, rules):

        """
        Replace(LABEL, SYMBOL)
        """
        for pair in rules:
            try:
                self.pcode = self.pcode.replace(pair[1], ' ' + pair[0] + ' ')
            except:
                pass
        """
        Replace(SYMBOL, LABEL)
        """
        for pair in rules:
            try:
                self.pcode = self.pcode.replace(pair[0], pair[1])
            except:
                pass
        """
        Delete useless space
        """
        tmplist = self.pcode.split(' ')
        newlist = list(filter(lambda x: x!='', tmplist))
        self.pcode = ' '.join(newlist)
        return
