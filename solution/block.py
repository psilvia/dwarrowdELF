from pwn import disasm, context

context.arch = 'amd64'

class Block:
    def __init__(self, i, code=None):
        self.code = code
        self.missing = 0
        self.done = False
        self.directions = ''
        self.level_prompts = 0
        self.id = i
    def __repr__(self):
        if self.id == None:
            return ''
        r = ''
        r += 'Id: %d\n' % self.id
        r += 'Code: \n\t' + (disasm(self.code + self.missing * '\x00') if self.code else '') + ' (%d missing)\n' % self.missing
        r += 'Directions: %s\n' % self.directions
        #r += 'Done: %s\n' % ('Yes' if self.done else 'No')
        #r += '===================================================\n'
        return r

    def smallformat(self):
        return 'Id: %d, %sDone' % (self.id, '' if self.done else '!')


