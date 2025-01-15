# Steg
### Help Trinity
#### Solution to the Neo Trinity Challenge

##### Challenge Description

In this challenge, participants are tasked with extracting a hidden flag from an image file using steganography techniques. The goal is to uncover the hidden message embedded within the image.

##### Steps to Solve the Challenge

##### Step 1: Upload the Image to AperiSolve

First, upload the provided image file to the [AperiSolve](https://aperisolve.fr/) website. AperiSolve is an online tool that analyzes images for hidden data using various steganography techniques.

##### Step 2: Analyze the Image

Once the image is uploaded, navigate to the **[+] Superimposed** section on the AperiSolve results page. This section reveals hidden data embedded within the layers of the image.

##### Step 3: Extract the Flag

In the **[+] Superimposed** section, you will find the hidden flag. The flag is encoded within a layer inside the image. For this challenge, the hidden flag is:

```
secuRIT{YOU_TOOK_TH3_R3D_P1LL_DIDNT_YOU}
```

#### Tools Used
- **AperiSolve**: An online tool for analyzing images for hidden data using steganography techniques. It supports multiple methods to uncover hidden messages within images.

#### Conclusion

By following these steps and using AperiSolve, participants can successfully uncover the hidden flag within the image. This challenge demonstrates the use of steganography techniques to hide and extract information. Good luck and happy hunting!
![[HelpTrinityColored.png]]
![[HelpTrinityAprisolve.png]]
### Dimensional Secrets
#### Challenge Description

You receive an audio file. Your task is to:

1. Decode the Morse code hidden in the audio
2. Decipher the text using a Caesar cipher with the audio length as the key
3. Add dots and slashs to the deciphered text to form a website URL
4. Find the flag, which is the product of the dimensions of the background picture on the website

#### Solution

##### Step 1: Decode the Morse Code

- Listen to the audio carefully
- Transcribe the Morse code (e.g., `... --- ... -.. --- - -.-. --- --`)
- Use an online Morse code decoder (like morsecode.world) to convert to text
- The decoded text is: `SHMXTQKBNLBGQNLOXRZM`
- OR use a morse audio to text converter tools like "[https://morsecode.world/international/decoder/audio-decoder-adaptive.html](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)"

##### Step 2: Caesar Cipher Decryption

- Check the length of the original audio file (25s)
- Use 25 as the key for the Caesar cipher
- Use an online Caesar cipher decoder (like cryptii.com)
- Input the decoded Morse code text and shift by 25
- The decrypted text is: `tinyurlcomchrompysan`

##### Step 3: Access the Website

- Add dots and slashs to the decrypted text to form a valid URL
- The URL is: `tinyurl.com/chrompysan`
- Open this URL in a web browser

##### Step 4: Find the Flag
- Download the image
- Check the image dimensions (619x127)
- Flag is the product of the dimensions

#### Flag

The flag is: `secuRITCTF{78613}`

#### Tools Used

- Audacity - for audio file manipulation
- morsecode.world - for Morse code decoding or audio decoding
- cryptii.com - for Caesar cipher decryption
- Web browser developer tools - for inspecting the website

#### Lessons Learned

- Audio manipulation and steganography techniques
- Morse code transcription and decoding
- Understanding and applying the Caesar cipher
- Web inspection and image analysis
- The importance of attention to detail in multi-step challenges

#### Conclusion

This challenge combined various elements of cryptography, steganography, and web analysis. It required participants to think creatively and use a combination of tools to progress through each step. The challenge emphasizes the importance of audio analysis in CTFs and demonstrates how information can be hidden in unconventional ways.
### Phunsukh Wangdu
This challenge involves extracting, assembling, and decoding a QR code hidden within image metadata. The flag is revealed by following the steps outlined below.
#### Step 1: Extracting the QR Code Pieces

The hidden QR code pieces are embedded in the image metadata. Here's how to extract them:

1. Visit [AperiSolve](https://www.aperisolve.com/).
2. Upload the given image to analyze its metadata.
3. Scroll down to locate the QR code pieces (e.g., `p1.jpg`, `p2.jpg`, etc.).
4. Download the ZIP file containing these pieces. (the hint that this is a qr can be taken from the fact that the binwalk part contains 400 images which seems kinda sus , I know it's difficult)

![[Pasted image 20250115101350.png]]
#### Step 2: Merging the QR Code Pieces
Use the below python script to merge the 400 images and make a qr code out of them
```python
from PIL import Image
import os
import re

def merge_qr_code_pieces(image_folder, output_path, grid_size=20):
    """
    Merge QR code pieces into a single QR code image.
    
    :param image_folder: Path to the directory containing QR code pieces.
    :param output_path: Path where the assembled QR code image will be saved.
    :param grid_size: Number of pieces along one dimension of the grid (default is 20).
    """
    files = os.listdir(image_folder)
    try:
        files.sort(key=lambda x: int(re.search(r'(\d+)', x).group(1)))
    except ValueError:
        print("Error: Could not parse the numeric part of the filenames.")
        return
    first_piece = Image.open(os.path.join(image_folder, files[0]))
    piece_width, piece_height = first_piece.size
    qr_width = piece_width * grid_size
    qr_height = piece_height * grid_size
    assembled_image = Image.new("RGB", (qr_width, qr_height))

    for i, file in enumerate(files):
        piece = Image.open(os.path.join(image_folder, file))
        x = (i % grid_size) * piece_width
        y = (i // grid_size) * piece_height
        assembled_image.paste(piece, (x, y))
    if not output_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        output_path += '.png'
    assembled_image.save(output_path)
    print(f"QR code assembled and saved at {output_path}")

if __name__ == "__main__":
    image_folder = r"PATH"  # Replace with your folder path
    output_path = r"PATH"  # Corrected output path
    merge_qr_code_pieces(image_folder, output_path)
```
#### Step 3: Scanning the QR Code
Use a QR code scanner to decode the assembled image. The decoded message contains the flag.
#### Final Output
The flag revealed by scanning the QR code is: 
![[Pasted image 20250115101505.png]]
```
flag-{sW1cH_t0_L1nUx}
```
#### Point Deduction And Hints

HINT 1: Try to analyse the binwalk content (-5)
HINT 2: Use aperisolve!!! (-10)
HINT 3: 400 images = (20x20) ?(-5)
HINT 4: Final hint : try making a qr code using the images!(-10)

### Covered or Concealed 
#### Description
A beginner level question based on Steganography.
#### Attached files
- index.html
- style.css
#### Summary
Find the hidden string inside the image using Steganography.  
Now, decrypt this Base64 encoded string 7 times to find the flag.
#### Detailed solution
- Inspecting the webpage, you will see three comments which will translate in English to "Decode me 7 times".
    
- Click the Solve Me button which opens an image in a new tab.
    
- Decrypt the image by any steganography tool or even an online website and you will get the following string of characters:
    

```
Vm0weE5GVXhSWGhYV0doVVlUSlNXVmxyWkZOV1ZteFZWR3RPV0ZKc1ducFdiRkpIVmpKS1IxZHFRbFZpUmtwRVZteFZlRkpXU25KaFJtaG9UV3hLYjFacVFtRlpWa3B6Vkc1T1lWSnRhRlJWYkZaelRURmFjbFZyU214U2EydzBXVEJXYjFkSFNrZFhiR2hXWVd0YVRGcEZXbUZYUlRGWldrWmFUbFp0ZDNwV1JscFhZVEZaZVZOcldrOVdWR3hZV1d4b2IxTkdVblJsUjNSVFZtdGFWbFZ0ZUd0aFZrcHlZMFprVjAxdVFsQmFSRVpoWkVaT2RWSnNTbGRTTTAwMQ==
```

- By the first looks itself, this looks like a Base64 encoded string.
- As the Hint says, by Decoding the above string 7 times you get the flag.
#### Flag
```
SECURITCTF{N0W_Y0U_KN0W_M7_F4V0UR1T3_NUM83R}
```
#### Hint 1: See Html Comments
#### Hint 2: The Hint 1s String is in image

# Reverse Engineering 
### OOPSies 
#### 1. Decompiling the `.class` File
1. Locate the provided `.class` file.
2. Use any online Java decompiler to convert it back to a `.java` file.
#### 2. Analyzing the Decompiled Code
1. Open the generated `.java` file in a text editor or IDE.
2. Look for interesting strings, comments, or encoded data.
You are supposed to get:
```java
   public class Securit {
   public static void main(String[] var0) {
      System.out.println("Hello from the other side!!");
      System.out.println("Do you get the reference? no?");
      System.out.println("Never mind");
      System.out.println("now that you have reached here, here's your present. unwrap this to find out");
      System.out.println("c2VjdXJpdHtTZWN1cml0WFphMiEzWWI4UXc5UGwwfQ==");
      System.out.println("remember it's a secret between us");
   }
}
```
#### 3. Identifying Base64-Encoded Data
1. Search for suspicious-looking strings in the code.
2. Extract any base64-encoded strings you find.
"c2VjdXJpdHtTZWN1cml0WFphMiEzWWI4UXc5UGwwfQ== "
#### 4. Decoding the Base64 String
Use any online Base64 decoder to get the flag.
After decoding, you are supposed to get: "securit{SecuritXZa2!3Yb8Qw9Pl0}"
#### 5. Submitting the flag
Flag: securit{SecuritXZa2!3Yb8Qw9Pl0}

### Prove Your Worth
##### Overview
The provided C++ code prompts the user to enter a password, processes it, and checks if it matches a predefined encrypted key using a specific set of transformations. The main function captures the user input and performs a substring operation to extract the actual password from a given format. The `checkPassword` function then applies several transformations to the password and compares it to the encrypted key.
##### Code Breakdown
#### `main` Function
1. **User Input**: The user is asked to enter the vault password.
2. **Extract Password**: The program expects the input in the format `secuRIT{password}`, where `password` is 32 characters long. It extracts the `password` part using `userInput.substr(8, userInput.length() - 9)`.
3. **Password Check**: The extracted password is passed to the `checkPassword` function.
4. **Result**: Based on the return value of `checkPassword`, it prints either "Access granted." or "Access denied!".
#### `checkPassword` Function
1. **Length Check**: Ensures the password is exactly 32 characters long.
2. **Transformation Steps**:
    - **Swap Adjacent Characters**: Swaps every pair of adjacent characters.
    - **Reverse String**: Reverses the entire string.
    - **Rotate Segments**: Rotates every 4-character segment such that the last character moves to the first position within the segment.
3. **Comparison**: Compares the transformed password to the encrypted key `"c4P__n0R4de3T_ls_833_tHsM_1aw4Y5"`.
##### Detailed Transformation Example
Given a password "abcd1234efgh5678ijkl9012mnop3456", the transformations would be:
1. **Initial Password**: `abcd1234efgh5678ijkl9012mnop3456`
2. **After Swapping Adjacent Characters**: `badc2143fehg6587jilk0921onmp4536`
3. **After Reversing the String**: `6354pmno1290klij7856ghef3412cdab`
4. **After Rotating 4-Character Segments**:
    - Segment `6354` becomes `4635`
    - Segment `pmno` becomes `opmn`
    - Segment `1290` becomes `0129`
    - Segment `klij` becomes `jkli`
    - Segment `7856` becomes `6785`
    - Segment `ghef` becomes `fghe`
    - Segment `3412` becomes `2341`
    - Segment `cdab` becomes `bcda`
    - Resulting String: `4635opmn0129jkli6785fghe2341bcda`

The transformed password is then compared with the encrypted key. If they match, access is granted.
To solve the problem, the user has to reverse engineer the encryption and create a program to decrypt the key provided in the source file, which then provides the user with the key which he requires to move forward. The key users get after decryption is '5w4YaM_1s_tH3_83sT_l34deR_n0_c4P' which is to be submitted in the format secuRIT{5w4YaM_1s_tH3_83sT_l34deR_n0_c4P}
##### Conclusion
This code presents a challenge due to the specific sequence of transformations required to validate the password. The hint provided in the comment is crucial for understanding the expected input format and the nature of the transformations. This ensures that users must comprehend and correctly implement the transformation steps to match the predefined encrypted key and gain access.
##### Code used to ENCRYPT:
```cpp
#include <iostream>
#include <string>
#include <algorithm>
using namespace std;

string encryptKey(const string& key) {
    if (key.size() != 32) {
        throw invalid_argument("Key must be 32 characters long.");
    }

    string encrypted_key = key;

    for (size_t i = 0; i < encrypted_key.size() - 1; i += 2) {
        swap(encrypted_key[i], encrypted_key[i + 1]);
    }

    reverse(encrypted_key.begin(), encrypted_key.end());

    for (size_t k = 0; k < encrypted_key.size(); k += 4) {
        rotate(encrypted_key.begin() + k, encrypted_key.begin() + k + 3, encrypted_key.begin() + k + 4);
    }

    return encrypted_key;
}

int main() {
    string key = "5w4YaM_1s_tH3_83sT_l34deR_n0_c4P";
    string encrypted_key = encryptKey(key);
    cout << "Encrypted key: " << encrypted_key << endl;
    return 0;
}
```
##### Code used to DECRYPT:
```cpp
#include <iostream>
#include <string>
#include <algorithm>
using namespace std;

// Function to decrypt the key
string decryptKey(const string& encrypted_key) {
    if (encrypted_key.size() != 32) {
        throw invalid_argument("Encrypted key must be 32 characters long.");
    }

    string key = encrypted_key;

    // Third pass: Rotate sections of 4 characters to the left by one position (reverse)
    for (size_t k = 0; k < key.size(); k += 4) {
        rotate(key.begin() + k, key.begin() + k + 1, key.begin() + k + 4);
    }

    // Second pass: Reverse the entire string back
    reverse(key.begin(), key.end());

    // First pass: Simple swap adjacent characters back
    for (size_t i = 0; i < key.size() - 1; i += 2) {
        swap(key[i], key[i + 1]);
    }

    return key;
}

int main() {
    string encrypted_key = "c4P__n0R4de3T_ls_833_tHsM_1aw4Y5";
    string decrypted_key = decryptKey(encrypted_key);
    cout << "Decrypted key: " << decrypted_key << endl;
    return 0;
}
```
### Secret Recipe
This challenge involves decoding a message hidden within a Chef script. The Chef programming language is designed to make programs look like cooking recipes. This challenge cleverly uses this language to encode a secret message.
#### Step 1: Compiling and Understanding the Chef Script
The Chef script uses ingredients (variables or data) and a method (operations) to build a string from ASCII values. Compile this script to convert the ASCII values into characters, resulting in a long string of numbers and letters.

- Use [https://esolangpark.vercel.app/ide/chef](https://esolangpark.vercel.app/ide/chef) to compile the Chef script.
![[Pasted image 20250115113937.png]]
#### Step 2: ASCII Decoding
The output from the Chef compiler is an ASCII-encoded text. Use an ASCII to text decoder to convert this output into a readable string.

- Use [ASCII to Text Decoder](https://codebeautify.org/ascii-to-text) to convert ASCII-encoded text to a readable format.
![[Pasted image 20250115114019.png]]
#### Step 3: Reading the Message
The decoded message instructs to read it in reverse. When reversed, it reveals a Base64 encoded string.
#### Step 4: Base64 Decoding
Decode the Base64 string using CyberChef at [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) to unveil the final secret message or flag.
#### Final Output
This flag is the secret ingredient mentioned in the challenge, symbolizing mastery in the culinary (and CTF) arts.
#### Conclusion
This challenge demonstrates the use of multiple encoding schemes and the Chef programming language to secure and obfuscate data. It's a fun and educational way to learn about different aspects of cybersecurity and encoding techniques.
### Security Info
# Web Exploitation 
### The Architect's Matrix Conundrum
##### Step 1: Peering Behind the Curtain

To challenge The Architect, explore the matrix's source code:

1. Right-click the matrix display and choose "View Page Source"
2. Examine the underlying HTML and JavaScript
##### Step 2: Uncovering the Fragments of Truth

The message is split into four parts, each concealed using different methods:

1. **Fragment One:** Hidden in plain sight within the HTML
    
    - Look for a div with a class suggesting concealment
    
    ```html
    <div class="hidden-in-plain-sight">secuRIT{hack_the</div>
    ```
    
2. **Fragment Two:** Inserted into the core array of the Matrix
    
    - Add to the JavaScript array
    
    ```js
    drops.push("_matrix_");
    ```
    
3. **Fragment Three:**
    
    ```js
    // Hint: The third part is what you're trying to hack
         const encodedPart = btoa("matrix");
    ```
    
4. **Fragment Four:**
    
    ```js
    const hiddenChars = "_securIT_style}";
    ```
    
##### Step 3: Assembling the Message

Combine all fragments in the correct sequence:

The Complete Truth Unveiled Putting it all together, we reveal the message: secuRIT{hack_the_RIT_matrix_securIT_style}

### Web of Deception
#### Step 1: Initial Clue

Upon visiting the main page, participants are greeted with the text "did anyone say ROBOTS??" and an image named "robots.txt.png". This hints at checking the `/robots.txt` file.
![[Pasted image 20250115121639.png]]
#### Step 2: Following the Trail
The `robots.txt` file reveals a path to `/riddle1.html`.
##### Riddle 1: Math Challenge

Solve the math riddle presented on this page. The answer can be calculated manually or found in the JavaScript source code of the page.
After solving the first riddle, a button appears that leads to `/riddle2.html`.
Ans: 1.72
##### Riddle 2: Physics Question

This page presents a physics question based on projectile motion. Again, solve manually or find the answer in the page's source code.
Correctly answering the physics question reveals a button to `/riddle3.html`.
Ans: 10.20
##### Riddle 3: Mental Ability

Answer the basic mental ability question. The solution is also embedded within the page's JavaScript.
Ans: 20
#### Step 3: Discovering the Secret Path

Successfully solving all three riddles reveals a "SECRET PATH" button, which redirects to `/secrets.html`.

#### Step 4: Decoding the Final Message

The `/secrets.html` page presents a long binary code. Decode this binary to text to reveal the final flag.
```binary 
01110011 01100101 01100011 01110101 01010010 01001001 01010100 01111011 01010010 00110001 01100100 01100100 01101100 00110011 01011111 01001101 00110100 00100100 01110100 00110011 01110010 01011111 00110001 00100100 01011111 00110001 01101101 01110000 01110010 00110011 00100100 00100100 01100101 01100100 01111101
```
#### Final Output

The decoded message is the flag: 
<span style="font-size: 24px; color: #FF6347; font-weight: bold;">secuRIT{R1ddl3_M4$t3r_1$_1mpr3$$ed}</span>

This flag represents the mastery of solving complex web-based riddles and understanding the deeper layers of web navigation and source code inspection.
#### Conclusion
The Web of Deception challenge tests a wide range of skills from logical thinking to technical web navigation prowess, emphasizing the importance of attention to detail in cybersecurity.
### Unmask The Admin
1. Open the login page in a browser and log in with the following credentials:
   - Username: `admin`
   - Password: `supersecret123`
2. After login, to access the flag, access the developer tools (`F12` or `Ctrl+Shift+I`).
3. In the **Application** tab, select Cookies under Storage.
4. Set the `isAdmin` cookie to `true` and refresh the page. The below JavaScript code will be executed:
   ```javascript
   document.cookie = "isAdmin=true";
   ```
5. Refresh the page to access the admin panel.
6. The encoded flag will be displayed. Copy the displayed Base64-encoded flag:
   ```
   c2VjdVJJVGN0Znt0aGlzX2lzX2Jhc2U2NF9lbmNvZGVkfQ==
   ```
7. Decode the flag using any Base64 decoder or using Python. Example using Python:
   ```python
   import base64
   encoded_flag = "c2VjdVJJVGN0Znt0aGlzX2lzX2Jhc2U2NF9lbmNvZGVkfQ=="
   decoded_flag = base64.b64decode(encoded_flag).decode('utf-8')
   print(decoded_flag)
   ```
8. The decoded flag is:
   ```
   secuRITctf{this_is_base64_encoded}
   ```
##### Decoded Flag: `
secuRITctf{this_is_base64_encoded}

# Miscellaneous 
### Snake Charmer
IF you couldnt score 30 points in the game, checkout this method:
1. **Inspect the Source Code**
    
    For those with coding knowledge, you can inspect the game's source code to find hidden information. The flag appears to be encoded within the JavaScript section of the source code.
    
2. **Find the Encoded Flag**
    
    The encoded flag is presented in Base64 format. Example of the encoded flag: `c2VjdVJJVHtzbjRrM19jaDRybTNyXzNsaXQzfQ==`
![[Pasted image 20250115133842.png]]
#### Decoding the Flag
To decode this, you can use any Base64 decoder. Here are two methods:
##### Using Python
```python

  import base64
  print(base64.b64decode("c2VjdVJJVHtzbjRrM19jaDRybTNyXzNsaXQzfQ==").decode())
  
```
#### Final Flag
After decoding the Base64 string, you will get the final flag:
secuRIT{sn4k3_ch4rm3r_3lit3}

By following these steps and utilizing the provided tools, participants can successfully complete the Snake Charmer Challenge and capture the flag. Good luck and happy hunting!
### Layers of Lies
##### Challenge Description

In this challenge, participants are required to extract a hidden flag from an image using steganography and basic encoding techniques. The challenge tests the participants' ability to use various tools and apply decoding methods to uncover the hidden message.
##### Steps to Solve the Challenge
###### Download the Image
First, download the provided image file. This file contains hidden data that needs to be extracted.

###### Extract Hidden Data Using Steganography Tools
Use steganography tools like **AperiSolve** or **CyberChef** to analyze the image. These tools can help in extracting data hidden using techniques like Least Significant Bit (LSB) encoding.

###### Analyze the Image with ZSteg in AperiSolve
Load the image into **AperiSolve** and navigate to the **ZSteg** section.  
In the ZSteg output, look for LSB data where it mentions the text `flag-`.

  imagedata .. text: "000AAA000"
  b1,r,lsb,xy .. text: "n:-5%yuQX`t<"
  b1,rgb,lsb,xy .. text: 69:flag-ONSWG5LSNF2GG5DGPN5W4Y3SPFYHI2LPNZPXO2LUNBPWM33SMVXHG2LDON6Q====
  b4,b,msb,xy .. file: MPEG ADTS, layer I, v2, 112 kbps, 24 kHz, JntStereo

Note the encrypted flag following the `flag-` prefix.

###### Decrypt the Encrypted Flag
The extracted flag is encrypted using Base32 encoding. Use a Base32 decoder to decrypt the flag.  
Tools like **CyberChef** can be used for this purpose. Select the **From Base32** operation in CyberChef and input the encrypted flag to obtain the decrypted message.

###### Capture The Flag
After decoding, you will get the flag in the following format:

  securitctf{encryption_with_forensics}
  

Congratulations! You have successfully captured the flag.

##### Tools Used
- **AperiSolve**: An online tool for steganography analysis that supports multiple steganography techniques, including ZSteg.
- **CyberChef**: A versatile web-based tool for performing various encoding, decoding, and data manipulation operations, including Base32 decoding.
## Crypto 
### Ciphered Reflections 
write a code or use atbash deciper [websites](https://rumkin.com/tools/cipher/atbash/) to decipher the flag.
atBash input: hvxfIRG{Wvxibk1r0m_T0w}
Flag: secuRIT{Decryp1i0n_G0d}
### The secret handshake
In this challenge, participants are required to implement the Diffie-Hellman key exchange protocol in Python. The goal is to compute the shared secret key between two parties, Alice and Bob, using given values for the prime number `p`, the base `g`, and their private keys `a` and `b`.
#### Steps to Solve the Challenge
##### Step 1: Compute Public Values

Each party computes their public value using the formula:

```
A = g^a mod p
```

```
B = g^b mod p
```

Where:

- `p` is the prime number
- `g` is the base
- `a` is Alice's private key
- `b` is Bob's private key

##### Step 2: Compute the Shared Secret Key
Both parties compute the shared secret key using each other's public values:

```
shared_secret_alice = B^a mod p
```

```
shared_secret_bob = A^b mod p
```

Where:

- `B` is Bob's public value
- `A` is Alice's public value

##### Python Implementation
Below is the Python code to perform the Diffie-Hellman key exchange:

```
# Given values
p = 23
g = 5
a = 6
b = 15
Step 1: Compute public values
A = pow(g, a, p)
B = pow(g, b, p)
Step 2: Compute the shared secret key
shared_secret_alice = pow(B, a, p)
shared_secret_bob = pow(A, b, p)
Verify both computed shared secret keys are equal
```
##### Output
When the above Python code is executed, it will produce the following output:

```
Alice's public value (A): 8
Bob's public value (B): 19
Shared secret key computed by Alice: 2
Shared secret key computed by Bob: 2
Shared keys match: True
```

#### Conclusion
By following these steps, participants can successfully implement the Diffie-Hellman key exchange protocol and verify that both parties compute the same shared secret key. This challenge demonstrates the basics of cryptographic key exchange using mathematical principles.

#### Final Flag
The Final Flag is secuRIT{2}
### Multibase
#### Challenge Description
In this challenge, participants are provided with two encoded strings. The task is to decode the first string multiple times to reveal a key, which will then be used to decode the second string using the Vigenère cipher to uncover the actual flag.

#### Given Data
1. Vm1wR1lXRXdOVWhWYTJoVVYwaENWbGxYZEV0WGJGSlZVbXQwYTJKSFVucFpWVll3WVZaR1ZVMUVhejA9
2. spoijbmjxw{!hKET3Ag575MNW!hWPArQJWKdUSNR7O7sQAsG0Gl@vKl}

#### Procedure
##### Step 1: Multi-layer Decoding
The first string `Vm1wR1lXRXdOVWhWYTJoVVYwaENWbGxYZEV0WGJGSlZVbXQwYTJKSFVucFpWVll3WVZaR1ZVMUVhejA9` needs to be decoded multiple times using Base64 decoding.

Decoding the string multiple times reveals the key: `almost_there`.

##### Step 2: Using the Key for Vigenère Cipher
The second string `spoijbmjxw{!hKET3Ag575MNW!hWPArQJWKdUSNR7O7sQAsG0Gl@vKl}` needs to be decoded using the Vigenère cipher with the key obtained from Step 1.

Decoding the second string with the key `almost_there` reveals the actual flag: `securitctf{!dKTH3Mo575TUP!dFLAgEVERkNOWN7O7hEMaN0Ne@rTh}`.
#### Tools Used
- **Base64 Decoder**: An online tool or Python script to decode the Base64 encoded string multiple times.
- **Vigenère Cipher Decoder**: An online tool or Python script to decode the Vigenère cipher text using the obtained key.
- #### Conclusion
By following these steps, participants can successfully decode the given strings to reveal the hidden flag. This challenge demonstrates the use of multi-layer decoding and the application of the Vigenère cipher. Good luck and happy decoding!
### A Twisted Message
Use an Encoder Decoder website such as *cryptii*
Use ROT13 method and put the given cipher text and get the flag which is securitctf{you_are_doing_good!_all_the_best}
### Give it a Cipher
In this problem, we first encounter hash values, and we can crack these hash values [here](https://crackstation.net/).Now that we have the original message, which says:
"Have you ever heard about RSA"

This means the next message is encrypted using the RSA algorithm, and we need a private key to decrypt the encrypted message. For this, we use this [website](https://www.devglan.com/online-tools/rsa-encryption-decryption) and get the flag.

#### Flag: secuRIT{RSA_with_SHA_is_easy}
# Forensic
### The Hidden Signature
#### Given:

We have received an image that seems to be corrupted. Can you fix the image and reveal the hidden message?

#### Challenge Description
In this challenge, we are given a corrupted jpeg image which on trying to open, fails to display properly or seems to corrupted. Our goal is to use a hex editor to inspect the first few bytes of the file and locate the incorrect to values in the file's header and replace them with the proper JPEG magic number. This process will fix the file and enable us to view the image correctly.
#### Procedure
#### Step 1: UnZip the file
After unzipping the file, you will now have a jpeg file which says "format is unsupported or file is corrupted".

#### Step 2: Get the JPEG File Signature (Magic Number)

Get the File Signature which for jpeg raw file is FF D8 FF E0. 
![[Pasted image 20250115151918.png]]

#### Step 3: Open Hex Editor
After opening the software, locate the unzipped image on the computer and open it in Hex Editor.

#### Step 4: Replace the Bits
Replace the first six bits of the file with the Magic Number found.
![[Pasted image 20250115151947.png]]

#### Step 5: Reopen the Image

Save the changes, and reopen the image. The image should now display the flag.

#### End Result:
![[Pasted image 20250115152052.png]]
#### Conclusion:

In this challenge, we successfully repaired a corrupted JPEG image by identifying and correcting the incorrect header values using a hex editor. By replacing the erroneous bytes with the correct JPEG magic number, we restored the image and revealed the hidden message. This exercise demonstrates the importance of understanding file signatures and the structure of different file formats.
#### Flag: secuRIT{you_are_genius}
### I Love It
#### Challenge Description
In this challenge, participants are given an MP3 file named **i_love_it.mp3**. At the end of the MP3 file, there is an odd beeping noise which participants should identify as Morse code. The task is to convert this Morse code into text to reveal the flag.
#### Steps to Solve the Challenge
##### Step 1: Listen to the Audio
Play the provided MP3 file **i_love_it.mp3** and listen carefully. At the end of the audio, you will hear a series of beeping noises.

##### Step 2: Identify the Morse Code
Recognize that the beeping noise is actually Morse code. The pattern of beeps and pauses corresponds to Morse code signals.

##### Step 3: Convert Morse Code to Text
Use an online service that converts audio Morse code to text. You can find various tools available online by searching for "audio Morse code to text converter".

Upload the MP3 file to the selected service and let it process the audio. The service will convert the Morse code to the following text:

```
secuRIT b33p b00p b33p
```

##### Step 4: Format the Flag

Format the extracted text into the correct flag format. The flag should be in the format `secuRIT{b33p_b00p_b33p}`. Therefore, the final flag is:

```
secuRIT{b33p_b00p_b33p}
```

#### Tools Used

- **Audio Morse Code to Text Converter**: An online service that converts audio Morse code signals to text. Various tools can be found by searching online.

#### Conclusion
By following these steps and using the provided hints, participants can successfully decode the Morse code at the end of the audio file to reveal the flag. This challenge demonstrates the use of Morse code for encoding messages within audio files. Good luck and happy hunting!
### Breaking RSA
Test Your Solution (Python)
```python
from sympy import mod_inverse
```
#### Given values
n = 3233
e = 17
ciphertext = 2201
#### Step 1: Find p and q (since n = p * q)
p = 61
q = 53

#### Step 2: Compute φ(n)
phi_n = (p - 1) * (q - 1)
#### Step 3: Compute the modular inverse of e
d = mod_inverse(e, phi_n)

#### Step 4: Decrypt the ciphertext
plaintext = pow(ciphertext, d, n)

**print(f"Decrypted message: {plaintext}")**

##### Conclusion
By following these steps and using AperiSolve, participants can successfully uncover the hidden flag within the image. This challenge demonstrates the use of steganography techniques to hide and extract information. Good luck and happy hunting!

#### Flag
Final Flag is secuRIT{2825}
### Time Traveller
Use *Wayback Machine* - An Internet archive!
Put the website with proper year, month and date 
Find the flag which is securitctf{webmaster@wipro.com}
# Theme based
### Harry Potter
First Flag: secuRIT{Y0u_Are_1HE_CH0sEn_ONe} -> base64 encoded (c2VjdVJJVHtZMHVfQXJlXzFIRV9DSDBzRW5fT05lfQ==)

Secound Question :- Which tool is being mentioned? -> Ans: Wireshark
Secound Flag: Who sent the message? (Keep it in the format secuRIT{} For eg: secuRIT{Ron}  ) -> Flag: secuRIT{darkl0rd}

Third Question :- Who is the new teacher in hogwarts? -> Ans: cookie_monster
Third Flag: secuRIT{C00kies_CaN_B3_Dang3rous!}
Hint: For knowing anyone truely, you need to know their background very well right? 
Hint: Once you are on path IncrementinG is the your way out
Hint: When we are on right path then we should belive on our gut feelings

Fourth Question :- Whats the vulnerability you are using here (ALL Caps) -> IDOR
Fourth Flag :- secuRIT{IDOR_S33mS_T0_B3_E4Sy}
Hint :- I think out professor is too lazy to change the creds :( 
Hint :- sorry my english is bad, but my ID OR number would be integer right?
Hint :- Can you access any other fan mails? 

Fifth Flag :- Whats the username? -> Ans darklord
Fifth Flag :- secuRIT{h0rcrux_D3stR0y3d!}
Hint :- The key to the vault lies within the password... but only for those who know the right spell. But when you dont have the key then what would you do?
Hint :- Are you scared of injections? Cause I am :(
Hint :- Try to provide spaces in the payload if you know what you doing ;)


### Money Heist: 
### A Heist in Layers
This walkthrough will guide you through solving each puzzle and uncovering the password to unlock `goal.zip`. Let’s dive in!
#### Shortcut:
the Instructions.txt gives a huge hint about `passwords_list.txt` in the Note section of the file it says :

```
- People who are lazy to solve puzzles i have given you a list of around 30,000 possible passwords.
- Best of luck for finding the oil drop hidden in ocean of water droplets.
```

Which shows that there is only one unique password in `passwords_list.txt` which can be obtained by executing the follwoing command: `sort passwords_list.txt | uniq -u`

#### Puzzle 1: The Vault Code
##### Problem:
A 6-digit code where:

1. The sum of the digits is 21.
2. All digits are distinct.
3. Digits are arranged in ascending order.

##### Solution:
- List all combinations of distinct digits (0–9) that sum to 21.
- The valid combination: **1, 2, 3, 4, 5, 6** (Sum = 21).
- Arrange in increasing order: **123456**.

**X1 = 123456**
#### Puzzle 2: The Alarm Code
##### Problem:
A cryptic poem hints at a code. The solution is the first alphabet of each line of the poem with words separated by underscores.

##### Solution:
The key phrase builds up as :  
**“TIME TO ROB”**

Format with underscores: **TIME_TO_ROB**

**X2 = TIME_TO_ROB**
##### Puzzle 3: Tokyo’s Hidden Escape
##### Problem:
Find the hidden phrase in the Lorem Ipsum text.
##### Solution:
- Spot the reversed phrase in the text: **"(KNAB_EHT)"**.
- Reverse it back: **"THE_BANK"**.

**X3 = THE_BANK**
#### Puzzle 4: The Final Puzzle
##### Problem:
Find the sum of factorials of numbers from 1 to 5.
##### Solution:
Factorials:

- 1! = 1
- 2! = 2
- 3! = 6
- 4! = 24
- 5! = 120  
    Sum = 1 + 2 + 6 + 24 + 120 = **153**

**X4 = 153**
#### Puzzle 5: The Security Lockdown
##### Problem:
Decrypt the Caesar cipher: “wkh khlvw ehjlqv”.  
Shift letters backward by 3.

##### Solution:
- Decoded text: **“THE HEIST BEGINS”**.
- Format with underscores and capitalize: **THE_HEIST_BEGINS**.

**X5 = THE_HEIST_BEGINS**
#### Puzzle 6: The Maze of Directions
##### Problem:
Calculate the shortest distance from the final position to the origin (0, 0) using the given movements.

##### Solution:
Final coordinates:

- North-South: 5 - 6 + 7 - 2 = **4**
- East-West: 3 - 4 + 8 - 5 = **2**

Shortest distance = √(4² + 2²) = √20.  
P = 20.

**X6 = 20**
#### Puzzle 7: The Treasure
##### Problem:
Find the largest prime number less than the prize pool of HackRITual.
##### Solution:
Assume the prize pool = **10,000** (example value).  
Largest prime less than 10,000: **9973**.

**X7 = 9973**
#### Final Password
Combine all fragments with underscores:  
`X1_X2_X3_X4_X5_X6_X7`

**Password = 123456_TIME_TO_ROB_THE_BANK_153_THE_HEIST_BEGINS_20_9973**

Use this password to unzip `goal.zip` and reveal the final goal. After unzipping you will find a goal.txt in the directory upon opening it you will find the flag like below:
#### Flag
goal.txt be accessible after unzipping. open the file.

##### FLAG: secuRIT{Th3_Profess0r_w0uld_b3_pr0ud!}
### In the memories
Welcome to the solution walkthrough of the **Vanishing File Heist**. In this challenge, you were tasked with recovering a deleted file from a bank's fragmented memory system. It required keen attention to file structures, searching techniques, and using **strings and grep** to locate the FLAG hidden in the depths of the system.
#### **Step 1: Starting the Challenge**

When you first begin, navigate to the `In_The_Memories` directory, where the bank’s entire system structure is hidden. This will be your starting point. Use the `cd` command to get into the base directory:

```shell
cd In_The_Memories
```
#### **Step 2: Finding the Right Path**
```shell
cd bank_system
```

In the `bank_system` directory, there are many files that appear irrelevant. These include random logs and binary files. **Do not focus on these just yet**—they are distractions.

The clue is hidden in a file called `hint.txt`. This file gives a clear indication that you need to follow a path leading to **/docs/file_3.txt**.

```shell
cat hint.txt
```

This will reveal a hint like:

```
cd docs 
cat file1.txt || file3.txt || file9.txt
```
#### **Step 3: Navigating the Docs**
Your next step is to enter the `docs` directory, which contains the text files . Here’s how to access it:

```shell
cd docs
```

and acc to the hint you should go through the file_1, file_3 and file_5. when you read file_3.txt using the following command:

```
cat file_3.txt
```

it reveals the next location you need to go to:

```
The first key lies in 'transactions'. Check :
txn_4.log,
txn_5.log,
txn_7.log for the next hint.
```

This shows our next location `transactions` directory.
#### **Step 4: Navigating the Transactions**
In Transactions try reading each of the txn_4.log, txn_5.log, txn_7.log While reading txn_7.log we will wind our next clue:

```shell
cd ..
cd transactions
cat txn_7.log
```

this will reveal our next target location where we will find our next hint:

```
You’re getting closer! Look in 'security'. The key lies in either 
sec_2.cfg
sec_4.cfg
sec_6.cfg
sec_8.cfg
```

So we get our next location which is securit
#### **Step 5: Navigating the Security**
Go to the security directory and read through the required files.

```shell
cd ..
cd security
cat sec_4.cgf
```

while reading sec_4.cfg we find our next clue:

```
The trail leads to 'reports'. Seek the answer in 
report_9.csv
report_8.csv
report_5.csv
report_4.csv
report_2.csv
```

The hunt for the flag is nealry half done. Reports will hold our next instructions.
#### **Step 6: Navigating the Reports**
Navigate to reports directory and read through the required files.

```shell
cd ..
cd reports
cat report_2.csv
```

while reading report_2.csv we find:

```
Almost there! The final step is hidden in 'software/memory_dump'.
```

#### **Step 7: Navigating the Memory Dump**
Your next step is to enter the `memory_dump` directory, which contains the fragmented data of deleted files. Here’s how to access it:

```shell
cd ..
cd software/memory_dump
```

Now, you’ll notice multiple files here. Some contain meaningless data, but others hide critical information.

**Important:** The key lies in one specific file that contains the **FLAG**—but it’s hidden among all the junk. You need to search through all files for strings that might reveal it.

You will also notice a hint3.txt file

```
cat hint3.txt
```

this will give us a really bug clue :

```
all the deleted files and Docs will be dumped here
tools to consider: strings * 
```
#### **Step 8: Using `strings` and `grep` to Find the FLAG**
To locate the FLAG, use the `strings` command to extract printable strings from all the binary files in the `memory_dump` folder. You’ll pipe this output into `grep` to search for the flag. Or you can just extract all the strings as well both will work just fine

Run this command only after entering the memory dump directory:

```shell
strings *
strings * | grep "FLAG"
```

this will reveal the flag :

```
bank_system/software/memory_dump$ strings *                                                                                                                                 all the deleted files and Docs will be dumped here                                                                                                                                                                                           tools to consider: strings *                                                                                                                                                                                                                 RandomMemoryData19289                                                                                                                                                                                                                        RandomMemoryData20430                                                                                                                                                                                                                        Random string ...Lots of such random strings and finally we reach the required                                                                                                                                                                                                                            Random string 14955                                                                                                                                                                                                                          Random string 24411                                                                                                                                                                                                                          Random string 20253                                                                                                                                                                                                                          Random string                                                                                                                                                Random data    flag                                                                                                                                                        secuRIT{D3L3T3D_#BUT_1S_N0T_4G0NE__TH3_PR0F3SS0R_W4TCH3S_&_H34RS_3V3RYTH1NG}                                                                                                                                                                 More random data                                                                                                                                                                                                                             Random string 15975                                                                                                                                                                                                                          Random string                                                                                                                                                Random string 8267                                                                                                                                                                                                                           RandomMemoryData1623                                                                                                                                                                                                                                                                                                                                                                        Random string 11113                                                                                                                                                                                                                          Random string 20372                                                                                                                                                                                                                          Random string 29212   and so on............
```

This is the output when we search for all the strings in the directory

```
strings * | grep "FLAG"
FLAG{D3L3T3D_#BUT_1S_N0T_4G0NE__TH3_PR0F3SS0R_W4TCH3S_&_H34RS_3V3RYTH1NG}
```

And this is the flag which is displayed directly when grep is used.

#### FLAG: 
 secuRIT{D3L3T3D_#BUT_1S_N0T_4G0NE__TH3_PR0F3SS0R_W4TCH3S_&_H34RS_3V3RYTH1NG}

### The Heist Unflods
#### **Overview**
This challenge is part of the Money Heist-themed CTF where participants uncover hidden clues across interconnected web pages to recover flag parts and unlock subsequent challenges. The full flag is:

`secuRIT{h4ckRITu4al_H31st_1n_Progress}`

Here, we explain step-by-step solutions for uncovering flag parts and solving the puzzles embedded within the Security Cameras challenge.

#### **Challenge 1: Retrieving** `flag_part1`
##### **Context**
- The first camera feed (`cam1.png`) contains hidden metadata that reveals `flag_part1`.

##### **Solution**
1. **Identify Metadata Clues:**
    
    - Use a tool like `exiftool` to inspect the metadata of `cam1.png`.
    
    ```shell
    exiftool cam1.png
    ```
    
2. **Extract the Metadata:**
    
    - Look for the `Comment` field, which contains:
        
        ```
        Comment: flag_part1: secuRIT{h4ck
        ```
        
3. **Answer:**
    
    - `flag_part1` = `secuRIT{h4ck`

#### AperiSolve
![[Pasted image 20250115163052.png]]
#### **Challenge 2: Retrieving** `flag_part2`

##### **Context**

- The second camera feed image (`cam2_route_to_[flag_part2].png`) hints at a dynamic binary puzzle located at `/secret_cameras/flag_part2`.

##### **Solution**
1. **Access the Puzzle Page:**
    
    - Navigate to `/secret_cameras/flag_part2` on the web app.
2. **Solve the Binary Puzzle:**
    
    - Flip the binary cells in the interactive grid to form the binary number `10101101`.
    - Submit the solution to reveal the next part of the flag and an additional clue for the next challenge.
3. **Output:**
    
    - Upon correct submission, the alert box reveals:
        
        ```
        Success! Flag Part 2: _R1Tu4l_
        
        Secret Quest: Solve the equation in Camera 2 feed to get the route to the next challenge!
        ```
        
4. **Answer:**
    
    - `flag_part2` = `_R1Tu4l_`

#### **Challenge 3: Retrieving** `flag_part3`
##### **Context**
- The third camera feed (`cam3.jpg`) contains semi-transparent text revealing `flag_part3`.

##### **Solution**
1. **Enhance Visibility:**
    
    - Use an image manipulation tool like ImageMagick to analyze the image and enhance visibility of the hidden text.
    
    ```shell
    sudo apt update
    sudo apt install imagemagick
    convert cam3.jpg -pointsize 72 -fill "rgba(255,255,255,0.5)" -gravity center -annotate +0+0 "flag_part3: H31st_" cam3_with_semi_transparent_text.jpg
    ```
    
2. **Extract the Flag:**
    
    - The annotation reveals `flag_part3: H31st_`.
3. **Answer:**
    
    - `flag_part3` = `H31st_`

#### AperiSolve
![[Pasted image 20250115163231.png]]
#### **Challenge 4: Retrieving**`flag_part4`
##### **Context**
- The fourth camera feed (`cam4.jpg`) contains an embedded file using steganography.

##### **Solution**
1. **Extract the Embedded File:**
    
    - Use `steghide` to extract the hidden file `flag_part_4.txt`.
    
    ```shell
    steghide extract -sf cam4.jpg
    ```
    
    - When prompted for a password, leave it blank or use the given clue.
2. **Read the File:**
    
    - The extracted file reveals:
        
        ```
        flag_part4: _1n_Progress}
        ```
        
3. **Answer:**
    
    - `flag_part4` = `_1n_Progress}`

#### AperiSolve
![[Pasted image 20250115163310.png]]
#### **Full Flag**
Combine all parts to reconstruct the full flag:

```
flag_part1: secuRIT{h4ck
flag_part2: _R1Tu4l_
flag_part3: H31st_
flag_part4: _1n_Progress}
```

#### Complete Flag:
**secuRIT{h4ckRITu4l_H31st_1n_Progress}**
#### **Secret Quest: Solving the Equation**
#### **Context**
- Camera 2's feed hints at solving an equation to unlock the route to the next medium-difficulty challenge.

##### **Solution**
1. **Equation Analysis:**
    
    - The equation hinted at in the feed simplifies to coordinates or clues for `/secret_cameras/TheProfessorsCommunications`.
2. **Solve the Equation:**
    
    - Example equation: `x + y = z`
    - Solve using provided parameters or clues.
3. **Unlock the Route:**
    
    - Correct solution reveals:
        
        ```
        Route to next challenge: /secret_cameras/TheProfessorsCommunications
        ```
        
#### **Tools and Commands Recap**
- **Steg Analysis:** `AperiSolve` gives solution for 1st,3rd, and the 5th image (provide password/paraphrase wherever required).
- **Metadata Analysis:** `exiftool`
- **Steganography:** `steghide`
- **Image Manipulation:** `ImageMagick``

This concludes the detailed solution for the Security Cameras challenge. Ensure all tools are installed and accessible before starting the CTF!
### Welcome to "The Professor's Communication" challenge
Welcome to the complete solution guide for the Money Heist-themed "The Professor's Communications" CTF challenge. This document will walk you through every stage, detailing the puzzles, hints, and solutions, along with the techniques and thought processes required to solve them.
#### **Overview of the Challenge**

##### **Objective**:
Players must navigate through various stages, solve encryption-based puzzles, manipulate cookies, and decrypt ciphers to piece together the final flag:

**Final Flag**: `secuRIT{M@n1pulate_Th3_H31st_S3cur1ty}`
##### **Structure**:

1. Initial Challenge: MD5 Hash and Robots.txt
2. Cookie Manipulation: Unlocking the Admin Panel
3. Admin Panel Challenges:
    - Book Cipher Puzzle
    - QR Code Decoding
4. Final Challenge: Riddle and Binary Decoding

Each stage provides either part of the flag or a route to the next challenge.
#### **Detailed Walkthrough**
##### **1. Initial Challenge**
###### **Task**:
Find the MD5 hash of the word "hello" and discover the robots.txt file. 
###### **Steps**:
1. Players are prompted to compute the MD5 hash of "hello".
    - MD5 hash of "hello": `5d41402abc4b2a76b9719d911017c592`.
2. Submitting the hash reveals a hint to check the `/robots.txt` file.
3. Accessing `/robots.txt` reveals:
    - A secret route: `/bella-ciao`
    - Hint: HESIT is the key!
![[Pasted image 20250115163807.png]]
##### **2. Cookie Manipulation**
###### **Task**:
Manipulate the `admin` cookie to unlock the Admin Panel.
###### **Steps**:
1. Visiting `/bella-ciao` prompts players to set the `admin` cookie to `true`.
2. Using browser developer tools:
    - Open the "Application" tab.
    - Edit the `admin` cookie value to `true`.
3. Refreshing the page redirects to the Admin Panel.
![[Pasted image 20250115163746.png]]
##### **3. Admin Panel Challenges**
###### **Challenge 1: Book Cipher Puzzle**
###### **Task**:
Solve a book cipher using text hosted at `/book`. Players must extract 5 words to form the solution.

###### **Steps**:
1. Visit `/book/<page>` to view the book pages. Example lines:
    - Page 1: "The quick brown fox jumps over the lazy dog."
    - Page 2: "In a hole in the ground, there lived a hobbit."
    - Page 3: "It was the best of times, it was the worst of times."
    - Page 4: "Call me Ishmael."
    - Page 5: "To be or not to be, that is the question."
2. The cipher provides indices to extract words from specific pages. Example:
    - Page 1, Word 2: `quick`
    - Page 2, Word 1: `hobbit`
    - Page 3, Word 6: `times`
    - Page 4, Word 2: `Ishmael`
    - Page 5, Word 4: `question`
3. Solution: `quick hobbit times Ishmael question`
4. Submitting this reveals `Correct! You've solved the Book Cipher.where does JavaScript print stuff 🤔` . 5.first part of the flag is printed onto the console `Flag Part 1/3: 'secuRIT{M@n1pulate_'`
![[Pasted image 20250115163953.png]]
![[Pasted image 20250115163959.png]]
###### **Challenge 2: Vigenere Cipher**
###### **Task**:
Decode a bencoded vigenere Code, using a key and retrieve the next part of the flag.
###### **Steps**:
1. Key was hinted to the players in the robots.txt = `HEIST`
2. The encoded message is given the participants `KIKJRWXQGG`.
3. Use any online decoder and decode the mssage : `DECRYPTION`.
    - submit it to get a secret route `route: /admin-panel/final-challenge`
![[Pasted image 20250115164035.png]]
###### **Challenge 3: QR Code Puzzle**
###### **Task**:
Decode a base64-encoded QR Code, scan it, and retrieve the next part of the flag.

###### **Steps**:
1. Players are given a base64 string representing the QR code.
    - Example: `iVBORw0KGgoAAAANSUhEUgAA...`
2. Decode the base64 string into an image file (using tools like Python or online decoders).
3. Scan the QR code using any QR scanner.
    - Scanned result reveals: `flag part 3/3: S3cur1ty}'`
![[Pasted image 20250115164102.png]]
##### **4. Final Challenge**
###### **Challenge 1: Solve the Riddle**
###### **Task**:
Solve the riddle to reveal the URL for the next challenge.

###### **Riddle**:
"Im always moving, yet I never go anywhere. You can’t buy me, but you can lose me. I’m not something you can catch. What am I"
###### **Solution**:
- Answer: `Time`
- Submitting the answer reveals: `Coming soon`
###### **Challenge 2: Decode the Binary**
###### **Task**:
Decode the binary sequence and reveal a crucial password fragment.
###### **Binary**:
`01100010 01101001 01101110 01100001 01110010 01111001`

#### **Steps**:

1. Convert the binary to text (using ASCII values):
    - `01100010 -> b`
    - `01101001 -> i`
    - `01101110 -> n`
    - `01100001 -> a`
    - `01110010 -> r`
    - `01111001 -> y`
2. Result: `binary`
3. Submitting the answer reveals: `2025 is the 2nd part of the password used to unlock hard challenges.`
4. Also reveals the second part of the flag :`flag part 2/3: Th3_H31st_`
##### **Flag Assembly**
Parts of the flag are collected throughout the challenge:

1. From `/robots.txt`: `secuRIT{Th3_Pr0f3ss0r_`
2. From Book Cipher: `_US3S_V1g3n3r3_`
3. From QR Code: `_F0R_PL4N5!}`

**Final Flag**: `secuRIT{M@n1pulate_Th3_H31st_S3cur1ty}`
#### **Essential Skills Required**

1. **Hashing**:
    
    - Compute MD5 hashes using tools like `hashlib` in Python or online MD5 generators.
2. **Cookie Manipulation**:
    
    - Use browser developer tools to edit cookies.
3. **Cryptography**:
    
    - Understand and solve Book Cipher and Vigenere Cipher challenges.
4. **Binary Decoding**:
    
    - Translate binary sequences into ASCII text.
5. **QR Code Decoding**:
    
    - Convert base64-encoded data to an image and scan it.

#### **Conclusion**
"The Professor's Communications" challenge showcases a blend of problem-solving, cryptography, and web exploitation skills, all wrapped in a captivating Money Heist theme. By progressively increasing difficulty, it ensures an engaging experience for participants, ultimately rewarding them with the complete flag upon successful completion.

### The Final Escape
#### **Challenge Overview**
This challenge is a multi-stage puzzle designed to test participants' problem-solving, reverse engineering, and cybersecurity skills. The stages are:

1. **Audio Frequency Analysis + SQL Injection**
2. **Geo Location + Cookies**
3. **Logs + Obfuscated Code**

Each stage reveals a part of the final flag, which is: `secuRIT{r0bb3d_4_b4nk_4nd_3sc4p3d_th3_p0l1c3_succ3ssfu11y}`

---

#### **Stage 1: Audio Frequency Analysis + SQL Injection**
##### **Challenge Description**
Participants are provided with an audio file. After analyzing the file, they extract a keyword that leads them to the next step. The webpage also contains an SQL injection vulnerability as a decoy.
##### **Solution**
1. **Audio Analysis**:
    - Load the audio file into any frequency analysis tool (e.g., Audacity, Sonic Visualizer).
    - Generate a Spectorgram any audio tools loads of thema re available online too. 2.**SQL Injection**:
    - On solving the SQL injection we get an image which gives a mapping of Frequency to Alphabet using which we analyse the spectrogram generated. this will give us **FREQUENCY**

3.**Input Validation**:

- Participants enter the keyword `FREQUENCY` into the webpage form.
- On submission, the backend validates the answer and reveals the **first part of the flag**:
    
    ```
    secuRIT{r0bb3ed_4_b4nk_
    ```
    
- A button also appears, directing participants to the **Geo Location + Cookies** stage.

---

#### **Stage 2: Geo Location + Cookies**
##### **Challenge Description**
Participants are directed to a **Geo Puzzle** page. They download a KML file, which contains famous Indian locations. The descriptions hint at cookies. Setting the `location` cookie to a specific value reveals the next step.
##### **Solution**
1. **KML File Analysis**:
    
    - Participants open the KML file in any online viewer (e.g., Google Earth).
    - The pins mark famous locations in India. One location (e.g., **Karachi Bakery**, Hyderabad) is famous for cookies. This location is the password.
2. **Setting the Cookie**:
    
    - Participants set the `location` cookie in their browser developer tools:
        
        ```js
        document.cookie = "location=MSRIT";
        ```
        
    - The page reloads and reveals the message `RUN to CANTEEN` where our team will be waiting to give out the **second part of the flag**:
        
        ```
        _4nd_3sc4p3d_th3
        ```
        
    - Along with this the route to the next part of the challenge will also be given.

---

#### **Stage 3: Logs + Obfuscated Code**
##### **Challenge Description**
Participants analyze an `access.log` file and identify a hidden endpoint (`/download-script`). The downloaded script is obfuscated, requiring reverse engineering to decode the final answer.

##### **Solution**
1. **Logs File Analysis**:
    
    - Participants are given an `access.log` file with multiple misleading entries.
    - The actual endpoint (`/download-script`) is hidden among decoy URLs like `/downloads/scripts/misc.js` and `/downloads/script-source`.
2. **Accessing the Script**:
    
    - They make a GET request to `/download-script` (via browser or tools like cURL).
    - The obfuscated JavaScript file (`encoded_script.js`) is downloaded.
3. **Decoding the Script**:
    
    - The script uses XOR encryption to hide the message. Here's how it works:
        
        ```js
        var _0x7d7b = [
            "\x24\x37\x29\x29\x25\x2D\x28", // Encoded message
            "\x46\x52\x45\x45\x44\x4F\x4D", // FREEDOM
            "\x62\x65\x6C\x6C\x61"         // bella (key)
        ];
        ```
        
    - The encoded message is XOR-decrypted using the key `bella`. When reversed, the output is:
        
        ```
        FREEDOM
        ```
        
4. **Submitting the Answer**:
    
    - Participants enter `FREEDOM` on the webpage.
    - The backend validates the answer and reveals the **third part of the flag**:
        
        ```
        _p0l1c3_succ3ssfu11y}
        ```
        

---

#### **Final Flag**

After completing all stages, participants assemble the full flag:

```
secuRIT{r0bb3d_4_b4nk_4nd_3sc4p3d_th3_p0l1c3_succ3ssfu11y}
```

---

#### **Hints and Tips**

1. Use online tools like Audacity, Google Earth, or Base64/XOR decoders for analysis.
2. Pay attention to details in the logs and scripts—misleading elements are added to confuse you.
3. For the Geo Puzzle, focus on the cookie hints in the descriptions.

---

#### **Challenge Notes**
- This multi-stage challenge combines various cybersecurity concepts: frequency analysis, SQL injection, file analysis, and reverse engineering.
- It's designed to teach participants attention to detail and multi-step problem-solving techniques.

