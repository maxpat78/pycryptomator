import zlib

class Wordscodec:
    def __init__(p, dictionary):
        "Initialize a dictionary with 4096 words"
        words = open(dictionary).readlines()
        words = [x for x in map(lambda x: x.strip('\n'), words)]
        if len(words) != 4096: raise BaseException('A 4096 words list is required!')
        p.dictionary = words

    def words2bytes(p, words):
        """Convert a list of words into a bytes sequence. Each word represents 
        12 raw bits and must belong to the 4096-words reference dictionary """
        n = 0
        b = bytearray()
        cb = 0
        for w in words:
            if w not in p.dictionary: raise BaseException('Word "%s" does not belong to dictionary' % w)
            i = p.dictionary.index(w) # get word 12-bit index
            n |= i # or with n
            cb += 1
            if cb == 2: # emit 3 bytes every 24 bits
                b += n.to_bytes(3,'big')
                n = 0
                cb = 0
                continue
            n <<= 12 # shift by 12 bits
        return b

    def bytes2words(p, s):
        """Convert a byte sequence (24-bit padded) into a words list. Each word represents 
        12 raw bits and must belong to the 4096-words reference dictionary"""
        if len(s) % 3: raise BaseException('Bytes sequence length must be 24-bit multiple!')
        words = []
        for g in [s[i:i+3] for i in range(0, len(s), 3)]: # group by 3 bytes
            n = int.from_bytes(g, 'big')
            i0 = n & 0xFFF
            i1 = (n & 0xFFF000) >> 12
            words += [p.dictionary[i1]]
            words += [p.dictionary[i0]]
        return words

    def blob(p, pk, hk):
        "Get a blob containing the Primary master key (32 bytes), the HMAC key (32 bytes) and a 16-bit checksum"
        b = pk+hk
        return b + p.crc(b)

    def validate(p, s):
        "Ensure the retrieved bytes sequence is a valid Cryptomator key"
        if len(s) != 66:  raise BaseException('Decoded master keys must be 512 bits long with 16-bit checksum!' % w)
        crc = zlib.crc32(s[:64])
        if crc.to_bytes(4,'little')[:2] != s[64:]:
            raise BaseException('Bad master keys checksum!')

    def crc(p, s):
        "Get the 16-bit checksum for the Cryptomator master keys"
        if len(s) != 64:  raise BaseException('Decoded master keys must be 512 bits long!')
        crc = zlib.crc32(s)
        return crc.to_bytes(4,'little')[:2]
