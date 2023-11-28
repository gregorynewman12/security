from cryptography.hazmat.primitives import hashes
import itertools, os

teststring = "theoijosf" # This is the test string to generate a hash from
bin_teststring = teststring.encode("utf-8") # Encodes the teststring in binary using utf-8
digest = hashes.Hash(hashes.SHA256()) # Initializes the hash generator
digest.update(bin_teststring) # Loads the teststring to be hashed
digest_pointer = digest.copy() # Copies this instance of the hasher so it can continue to be used even after calling finalize()
result = digest.finalize() # Outputs the hash to result
original_hash = result[:3]  # Truncates the hash to a 24-bit (3 byte) value


# Strong collision resistance section
print("Searching for strong collision...")

# Characters used to generate random strings of length 4
characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789<>?:"[]!@#$%^&*()_-+='
string_length = 4

# Generate all possible strings of length 4 using the characters above.
possible_strings = [''.join(candidate) for candidate in itertools.product(
    characters, repeat=string_length)]


count = 0
sc_found = False
hashStorage = set()
while True:
    count += 1
    currDigest = digest_pointer
    randString = os.urandom(3)
    currDigest.update(randString)
    # Saves the current digest so it isn't closed when finalize() is called
    digest_pointer = currDigest.copy()
    result = currDigest.finalize()
    truncated_result = result[:3]  # Takes 6 bytes from the hash
    if truncated_result in hashStorage:
        print("\n\nStrong collision found.")
        print("It took " + str(count) + " attempts to find a matching hash\n")
        sc_found = True
        break
    else:
        hashStorage.add(truncated_result)
if sc_found == False:
    print("Strong collision not found.\n")
    


# Weak collision resistance section        

wc_found = False
count = 0 # Tracks the number of strings tried
print("Searching for weak collision...")
for member in possible_strings:
    count += 1
    currDigest = digest_pointer
    bin_member = member.encode("utf-8")
    currDigest.update(bin_member)
    # Saves the current digest so it isn't closed when finalize() is called
    digest_pointer = currDigest.copy()
    result = currDigest.finalize()
    truncated_result = result[:3]  # Takes 3 bytes from the hash
    if truncated_result == original_hash:
        print("\n\nWeak collision found.")
        print("It took " + str(count) + " attempts to find a matching hash")
        print("Original hash: " + str(original_hash))
        print("Matching hash: " + str(truncated_result))
        wc_found = True
        break

if wc_found == False:
    print("Weak collision not found.\n")
